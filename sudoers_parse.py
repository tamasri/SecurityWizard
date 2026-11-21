"""Sudoers parser and rule classifier for SecurityWizard.

Parses sudoers lines (including line continuations, comments, Defaults,
aliases, %group, negation, tags like NOPASSWD:/PASSWD:/SETENV:/NOEXEC:)
and returns typed rule objects.

Provides classify_rule() which returns (severity, reason) where severity
is one of STATUS_PASS, STATUS_WARNING, STATUS_CRITICAL, STATUS_INFO,
STATUS_SKIPPED.
"""

import builtins
import glob
import logging
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

builtins_open = builtins.open

logger = logging.getLogger(__name__)

# Severity constants (mirror common.py status strings)
STATUS_PASS = "PASS"  # nosec B105
STATUS_WARNING = "WARNING"
STATUS_CRITICAL = "CRITICAL"
STATUS_INFO = "INFO"
STATUS_SKIPPED = "SKIPPED"

# GTFOBins-style commands that can spawn a shell or escalate privileges
_RISKY_COMMANDS = frozenset(
    """
    7z [ anacron ar arp as at awk basename bash batch bc blkid bunzip2 bzip2 bzr c++ cal cat cc chattr chgrp
    chmod chown chroot clang clang++ cmake cmp comm containerd cp crontab csh ctr curl cut dash date dc dd
    ddrescue df diff diff3 dig dirname dmesg docker du egrep emacs env export expr false fdisk fgrep file
    find firewall-cmd free ftp ftrace g++ gawk gcc gdb git grep groups gunzip gzip head helm hexdump hg host
    htop id ifconfig init install ionice iostat ip ip6tables iptables join journalctl kill killall kprobe
    ksh kubectl ld ldd less ln locate lsblk lscpu lsmem ltrace lua lz4 make mawk mkdir more mount mpstat mv
    nano nc ncat netcat newgrp nft nice ninja nm nmap node nodejs nohup nsenter nslookup objdump od parted
    paste patch perf perl php ping ping6 pkill podman ps python python2 python3 python3.0 python3.1
    python3.10 python3.11 python3.12 python3.2 python3.3 python3.4 python3.5 python3.6 python3.7 python3.8
    python3.9 ranlib rar readelf realpath rm rmdir route rsh rsync ruby scp screen sed seq service set
    setsid sftp sg sh shuf sleep sort ssh stat strace strings strip su svn syslog systemctl tail tar tclsh
    tcsh tee telnet test time timeout tmux top touch tr tracepath traceroute true ufw umount uname uniq
    unlink unlz4 unrar unset unshare unxz unzip updatedb uptime users valgrind vi vim vmstat w watch wc wget
    who wish xargs xz yes zip zsh
    """.split()
)

# Commands that are safe when given a single exact path (no wildcard)
_SAFE_EXACT_COMMANDS = frozenset(
    """
    7z [ anacron ar arp as at awk basename bash batch bc blkid bunzip2 bzip2 bzr c++ cal cat cc chattr chgrp
    chmod chown clang clang++ cmake cmp comm containerd cp crontab csh ctr curl cut dash date dc dd df diff
    diff3 dig dirname dmesg docker du egrep emacs env export expr false fdisk fgrep file find firewall-cmd
    free ftp ftrace g++ gawk gcc gdb git grep groups gunzip gzip head helm hexdump hg host htop id ifconfig
    init install ionice iostat ip ip6tables iptables join journalctl kill killall kprobe ksh kubectl ld less
    ln locate ls lsblk lscpu lsmem ltrace lua lz4 make mawk mkdir more mpstat mv nano nc ncat netcat newgrp
    nft nice ninja nm node nodejs nohup nslookup objdump od parted paste patch perf perl php ping ping6
    pkill podman ps python python2 python3 ranlib rar readelf realpath rm rmdir route rsh rsync ruby scp
    screen sed seq service set setsid sftp sg sh shuf sleep sort ssh strace strings strip su svn syslog
    systemctl tail tar tclsh tcsh telnet test time timeout tmux top touch tr tracepath traceroute true ufw
    uname uniq unlink unlz4 unrar unset unxz unzip updatedb uptime users valgrind vi vim vmstat w watch wc
    wget who wish xargs xz yes zip zsh
    """.split()
)


@dataclass
class SudoRule:
    """A parsed sudoers rule."""

    user: str
    hosts: List[str]
    runas: List[str]
    tags: List[str]
    commands: List[str]
    source_file: str
    line: int
    negated: bool = False
    raw: str = ""


# ---------------------------------------------------------------------------
# Alias resolution
# ---------------------------------------------------------------------------


def _parse_aliases(content: str) -> Dict[str, List[str]]:
    """Parse User_Alias, Cmnd_Alias, Runas_Alias, Host_Alias definitions."""
    aliases: Dict[str, List[str]] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if (
            stripped.startswith("User_Alias")
            or stripped.startswith("Cmnd_Alias")
            or stripped.startswith("Runas_Alias")
            or stripped.startswith("Host_Alias")
        ):
            parts = stripped.split("=", 1)
            if len(parts) == 2:
                alias_name = parts[0].strip().split()[1]
                values = [v.strip() for v in parts[1].split(",") if v.strip()]
                aliases[alias_name] = values
    return aliases


def _resolve_aliases(value: str, aliases: Dict[str, List[str]]) -> List[str]:
    """Resolve an alias name to its values, or return the single value."""
    if value in aliases:
        return aliases[value]
    return [value]


# ---------------------------------------------------------------------------
# Line continuation handling
# ---------------------------------------------------------------------------


def _join_continuations(lines: List[str]) -> List[Tuple[str, int]]:
    """Join lines ending with backslash into logical lines.

    Returns a list of (logical_line, start_line_number) tuples.
    """
    logical_lines: List[Tuple[str, int]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        start = i + 1  # 1-based
        while line.rstrip().endswith("\\") and i + 1 < len(lines):
            line = line.rstrip()[:-1] + lines[i + 1]
            i += 1
        logical_lines.append((line, start))
        i += 1
    return logical_lines


# ---------------------------------------------------------------------------
# Parsing a single sudoers rule line
# ---------------------------------------------------------------------------


def _parse_rule_line(line: str, source_file: str, line_num: int, aliases: Dict[str, List[str]]) -> Optional[SudoRule]:
    """Parse a single sudoers rule line.

    Returns a SudoRule or None if the line is not a rule (Defaults, alias,
    comment, blank, etc.).
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    # Skip Defaults lines
    if stripped.startswith("Defaults"):
        return None

    # Skip alias definitions
    if (
        stripped.startswith("User_Alias")
        or stripped.startswith("Cmnd_Alias")
        or stripped.startswith("Runas_Alias")
        or stripped.startswith("Host_Alias")
    ):
        return None

    # Skip #include and #includedir
    if stripped.startswith("#include") or stripped.startswith("#includedir"):
        return None

    # Split on the first '=' to separate user/host part from runas/command part
    # Format: user host=(runas) [TAGS:] cmd, cmd, ...
    # Or: user host=(runas) cmd, cmd, ...
    # Or: user host=cmd, cmd, ... (no runas)

    # Find the first '=' or '('
    eq_idx = stripped.find("=")
    paren_idx = stripped.find("(")

    if eq_idx == -1 and paren_idx == -1:
        # No '=' or '(' - not a valid rule
        return None

    if eq_idx != -1 and (paren_idx == -1 or eq_idx < paren_idx):
        # Format: user host=(runas) ... or user host=cmd ...
        left = stripped[:eq_idx].strip()
        right = stripped[eq_idx + 1 :].strip()
    else:
        # Format: user host=(runas) ...
        # The '=' is inside the parentheses
        left = stripped[:paren_idx].strip()
        # Find the matching ')'
        depth = 0
        end_paren = -1
        for j in range(paren_idx, len(stripped)):
            if stripped[j] == "(":
                depth += 1
            elif stripped[j] == ")":
                depth -= 1
                if depth == 0:
                    end_paren = j
                    break
        if end_paren == -1:
            return None
        right = stripped[end_paren + 1 :].strip()
        # left is "user host"
        # right is "[TAGS:] cmd, cmd, ..."
        # runas_part is the runas list
        pass

    # Parse user and host from left
    # left is like "user host" or "user ALL" or "%group ALL"
    user_host_parts = left.split()
    if len(user_host_parts) < 2:
        # Could be just "user" with implicit ALL host
        user = user_host_parts[0]
        hosts = ["ALL"]
    else:
        user = user_host_parts[0]
        hosts_raw = user_host_parts[1]
        hosts = _resolve_aliases(hosts_raw, aliases)

    # Resolve user aliases
    user_values = _resolve_aliases(user, aliases)
    # Use the first user value for the rule (or join them)
    user_str = user_values[0] if len(user_values) == 1 else ",".join(user_values)

    # Check for negation
    negated = user_str.startswith("!")
    if negated:
        user_str = user_str[1:]

    # Parse runas
    if eq_idx != -1 and (paren_idx == -1 or eq_idx < paren_idx):
        # Format: user host=(runas) ... or user host=cmd ...
        # right starts with either (runas) or cmd
        if right.startswith("("):
            # Find matching ')'
            depth = 0
            end_paren = -1
            for j in range(len(right)):
                if right[j] == "(":
                    depth += 1
                elif right[j] == ")":
                    depth -= 1
                    if depth == 0:
                        end_paren = j
                        break
            if end_paren == -1:
                return None
            runas_raw = right[1:end_paren].strip()
            rest = right[end_paren + 1 :].strip()
        else:
            runas_raw = "root"
            rest = right
    else:
        # Format: user host=(runas) [TAGS:] cmd, cmd, ...
        # runas_part already extracted
        rest = right

    # Resolve runas aliases
    runas_values = []
    for rv in runas_raw.split(","):
        rv = rv.strip()
        if rv:
            runas_values.extend(_resolve_aliases(rv, aliases))

    # Parse tags and commands from rest
    # rest is like "NOPASSWD: cmd1, cmd2" or "cmd1, cmd2" or "PASSWD: cmd1"
    tags: List[str] = []
    commands: List[str] = []

    if rest:
        # Check for tags before the first command
        # Tags are like "NOPASSWD:", "PASSWD:", "SETENV:", "NOEXEC:"
        # They appear before the first command
        tag_pattern = re.compile(r"^(NOPASSWD|PASSWD|SETENV|NOEXEC)\s*:")
        while True:
            m = tag_pattern.match(rest)
            if m is None:
                break
            tags.append(m.group(1))
            rest = rest[m.end() :].strip()
        command_part = rest

        # Parse commands (comma-separated)
        for cmd in command_part.split(","):
            cmd = cmd.strip()
            if cmd:
                commands.append(cmd)
    else:
        # No commands - this is a Defaults-like line or malformed
        return None

    if not commands:
        return None

    # Resolve command aliases
    resolved_commands: List[str] = []
    for cmd in commands:
        resolved_commands.extend(_resolve_aliases(cmd, aliases))
    commands = resolved_commands

    return SudoRule(
        user=user_str,
        hosts=hosts,
        runas=runas_values,
        tags=tags,
        commands=commands,
        source_file=source_file,
        line=line_num,
        negated=negated,
        raw=stripped,
    )


# ---------------------------------------------------------------------------
# Parse a sudoers file
# ---------------------------------------------------------------------------


def parse_sudoers_file(path: str) -> List[SudoRule]:
    """Parse a sudoers file and return a list of SudoRule objects."""
    try:
        with builtins_open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as exc:
        logger.warning("Failed to read sudoers file %s: %s", path, exc)
        return []

    aliases = _parse_aliases(content)
    lines = content.splitlines()
    logical_lines = _join_continuations(lines)

    rules: List[SudoRule] = []
    for logical_line, start_line in logical_lines:
        rule = _parse_rule_line(logical_line, path, start_line, aliases)
        if rule is not None:
            rules.append(rule)

    return rules


def parse_sudoers_paths(paths: List[str]) -> List[SudoRule]:
    """Parse multiple sudoers files and return all rules."""
    all_rules: List[SudoRule] = []
    for path in paths:
        all_rules.extend(parse_sudoers_file(path))
    return all_rules


# ---------------------------------------------------------------------------
# Classify a rule
# ---------------------------------------------------------------------------


def _has_wildcard(command: str) -> bool:
    """Check if a command string contains a wildcard (*)."""
    return "*" in command


def _command_base_name(command: str) -> str:
    """Extract the base name of a command (strip path and arguments)."""
    # Remove wildcard and arguments
    cmd = command.split()[0] if command.split() else command
    # Remove path
    if "/" in cmd:
        cmd = cmd.rsplit("/", 1)[-1]
    return cmd


def _is_risky_command(command: str) -> bool:
    """Check if a command is in the risky GTFOBins list."""
    base = _command_base_name(command)
    # Check exact match or prefix match (e.g., python3.12 matches python3)
    if base in _RISKY_COMMANDS:
        return True
    # Check prefix match for versioned commands
    for risky in _RISKY_COMMANDS:
        if base.startswith(risky) and (len(base) == len(risky) or base[len(risky)] == "."):
            return True
    return False


def _is_narrow_command(command: str) -> bool:
    """Check if a command is a narrow, safe command (not in risky list)."""
    base = _command_base_name(command)
    return base not in _RISKY_COMMANDS


def _is_shell_or_interpreter(command: str) -> bool:
    """Check if a command is a shell or interpreter."""
    base = _command_base_name(command)
    shells = {
        "sh",
        "bash",
        "dash",
        "zsh",
        "ksh",
        "csh",
        "tcsh",
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "php",
        "node",
        "nodejs",
        "lua",
        "tclsh",
        "wish",
    }
    if base in shells:
        return True
    for s in shells:
        if base.startswith(s) and (len(base) == len(s) or base[len(s)] == "."):
            return True
    return False


def classify_rule(rule: SudoRule, config=None) -> Tuple[str, str]:
    """Classify a sudoers rule and return (severity, reason).

    severity is one of STATUS_PASS, STATUS_WARNING, STATUS_CRITICAL,
    STATUS_INFO, STATUS_SKIPPED.
    reason is a human-readable explanation.
    """
    # Check if the rule is allowed by config
    if config is not None:
        for cmd in rule.commands:
            if config.allowed_sudo_rule(rule.user, cmd) is not None:
                return (STATUS_INFO, "Allowed by config: %s can run %s" % (rule.user, cmd))

    # Negated rules are less concerning
    if rule.negated:
        return (STATUS_INFO, "Negated rule: !%s" % rule.user)

    # Check for NOPASSWD: ALL
    has_nopasswd = "NOPASSWD" in rule.tags
    has_all_command = "ALL" in rule.commands

    if has_nopasswd and has_all_command:
        return (
            STATUS_CRITICAL,
            "NOPASSWD: ALL - %s can run any command as %s without a password" % (rule.user, ",".join(rule.runas)),
        )

    # Check for wildcard arguments on shell/interpreter/editor commands
    for cmd in rule.commands:
        if _has_wildcard(cmd):
            base = _command_base_name(cmd)
            if _is_shell_or_interpreter(cmd) or base in {
                "vim",
                "vi",
                "nano",
                "less",
                "more",
                "find",
                "awk",
                "env",
                "tar",
                "rsync",
                "docker",
                "systemctl",
            }:
                return (
                    STATUS_CRITICAL,
                    "Wildcard argument on %s: %s can run %s with wildcard" % (base, rule.user, cmd),
                )

    # Check for risky commands (GTFOBins-style)
    for cmd in rule.commands:
        if _is_risky_command(cmd):
            base = _command_base_name(cmd)
            if has_nopasswd:
                return (
                    STATUS_CRITICAL,
                    "NOPASSWD with risky command %s: %s can run %s without a password" % (base, rule.user, cmd),
                )
            return (STATUS_WARNING, "Risky command %s: %s can run %s" % (base, rule.user, cmd))

    # Narrow rule: single exact command
    if len(rule.commands) == 1 and not _has_wildcard(rule.commands[0]):
        cmd = rule.commands[0]
        base = _command_base_name(cmd)
        if has_nopasswd:
            return (STATUS_INFO, "NOPASSWD with narrow command: %s can run %s without a password" % (rule.user, cmd))
        return (STATUS_INFO, "Narrow rule: %s can run %s" % (rule.user, cmd))

    # Multiple commands, no wildcards, no risky commands
    if has_nopasswd:
        return (STATUS_INFO, "NOPASSWD with %d commands: %s" % (len(rule.commands), ",".join(rule.commands)))
    return (STATUS_INFO, "%d commands: %s" % (len(rule.commands), ",".join(rule.commands)))


# ---------------------------------------------------------------------------
# Parse all sudoers files
# ---------------------------------------------------------------------------


def parse_all_sudoers() -> List[SudoRule]:
    """Parse /etc/sudoers and /etc/sudoers.d/* and return all rules."""
    paths: List[str] = []
    if os.path.isfile("/etc/sudoers"):
        paths.append("/etc/sudoers")
    for f in sorted(glob.glob("/etc/sudoers.d/*")):
        if os.path.isfile(f):
            paths.append(f)
    return parse_sudoers_paths(paths)
