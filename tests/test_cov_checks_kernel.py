"""checks_kernel: sysctl hardening checks (all sysctl reads and host probes are mocked)."""

import pytest

import checks_kernel
from common import STATUS_CRITICAL, STATUS_PASS, STATUS_SKIPPED, STATUS_WARNING, CmdResult

VALID_STATUSES = {"PASS", "WARNING", "CRITICAL", "INFO", "SKIPPED"}

ALL_CHECKS = [
    checks_kernel._check_rpf,
    checks_kernel._check_accept_redirects,
    checks_kernel._check_send_redirects,
    checks_kernel._check_syncookies,
    checks_kernel._check_source_route,
    checks_kernel._check_dmesg_restrict,
    checks_kernel._check_kptr_restrict,
    checks_kernel._check_bpf_jit_harden,
    checks_kernel._check_tcp_rfc1337,
    checks_kernel._check_secure_redirects,
    checks_kernel._check_ptrace_scope,
    checks_kernel._check_protected_hardlinks,
    checks_kernel._check_protected_symlinks,
    checks_kernel._check_unprivileged_bpf,
    checks_kernel._check_aslr,
]
IDS = [fn.__name__.replace("_check_", "") for fn in ALL_CHECKS]


def _assert_well_formed(result):
    assert set(result) >= {"id", "category", "title", "status", "what_it_checks", "risk", "command"}
    assert result["category"] == "kernel" and result["id"].startswith("KRN-")
    assert result["status"] in VALID_STATUSES
    assert result["title"] and result["what_it_checks"] and result["risk"]
    if result["status"] == STATUS_SKIPPED:
        assert result["current_value"], "a skipped check must say why"
    else:
        assert result["current_value"] and result["recommended_value"] or result["status"] == STATUS_PASS


def _sysctl(monkeypatch, value=None, found=True, per_key=None):
    def read(key):
        if per_key is not None:
            return per_key[key] if key in per_key else (False, "")
        return (found, value if found else "")

    monkeypatch.setattr(checks_kernel, "_read_sysctl", read)


@pytest.mark.parametrize("multi_homed", [False, True])
@pytest.mark.parametrize("value", ["0", "1", "2", "3", "4", "garbage"])
@pytest.mark.parametrize("fn", ALL_CHECKS, ids=IDS)
def test_every_check_returns_a_well_formed_result_for_any_value(monkeypatch, fn, value, multi_homed):
    _sysctl(monkeypatch, value)
    monkeypatch.setattr(checks_kernel, "_is_container_or_multihomed", lambda: multi_homed)
    _assert_well_formed(fn())


@pytest.mark.parametrize("fn", ALL_CHECKS, ids=IDS)
def test_missing_key_is_skipped_with_a_reason(monkeypatch, fn):
    _sysctl(monkeypatch, found=False)
    result = fn()
    assert result["status"] == STATUS_SKIPPED
    assert "not found" in result["current_value"] or "not" in result["current_value"].lower()


@pytest.mark.parametrize("fn", ALL_CHECKS, ids=IDS)
def test_unexpected_errors_become_skipped_results(monkeypatch, fn):
    def boom(key):
        raise RuntimeError("sysctl exploded")

    monkeypatch.setattr(checks_kernel, "_read_sysctl", boom)
    result = fn()
    assert result["status"] == STATUS_SKIPPED and "sysctl exploded" in result["current_value"]


def test_every_check_has_a_distinct_id(monkeypatch):
    _sysctl(monkeypatch, "1")
    monkeypatch.setattr(checks_kernel, "_is_container_or_multihomed", lambda: False)
    ids = [fn()["id"] for fn in ALL_CHECKS]
    assert len(set(ids)) == len(ids) == 15


def test_run_checks_runs_all_fifteen(monkeypatch):
    _sysctl(monkeypatch, "1")
    monkeypatch.setattr(checks_kernel, "_is_container_or_multihomed", lambda: False)
    results = checks_kernel.run_checks()
    assert len(results) == 15 and [r["id"] for r in results] == sorted([r["id"] for r in results], key=lambda i: i)


# ---- exact semantics -------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "multi_homed, value, expected",
    [
        (False, "1", STATUS_PASS),
        (False, "2", STATUS_WARNING),
        (False, "0", STATUS_CRITICAL),
        (False, "3", STATUS_WARNING),
        (True, "2", STATUS_PASS),  # loose mode is correct on Docker / multi-homed hosts
        (True, "1", STATUS_PASS),
        (True, "0", STATUS_WARNING),
        (True, "3", STATUS_WARNING),
    ],
)
def test_rp_filter_depends_on_the_host_type(monkeypatch, multi_homed, value, expected):
    _sysctl(monkeypatch, value)
    monkeypatch.setattr(checks_kernel, "_is_container_or_multihomed", lambda: multi_homed)
    result = checks_kernel._check_rpf()
    assert result["status"] == expected and result["id"] == "KRN-001"
    if multi_homed:
        assert "=2" in result["manual_command"] and "=1" not in result["manual_command"]  # never recommend strict here


def test_rp_filter_needs_both_keys(monkeypatch):
    _sysctl(monkeypatch, per_key={"net.ipv4.conf.all.rp_filter": (True, "1")})
    assert checks_kernel._check_rpf()["status"] == STATUS_SKIPPED


def test_rp_filter_mixed_values_on_a_plain_host(monkeypatch):
    _sysctl(
        monkeypatch,
        per_key={"net.ipv4.conf.all.rp_filter": (True, "1"), "net.ipv4.conf.default.rp_filter": (True, "0")},
    )
    monkeypatch.setattr(checks_kernel, "_is_container_or_multihomed", lambda: False)
    assert checks_kernel._check_rpf()["status"] == STATUS_CRITICAL


@pytest.mark.parametrize(
    "v4, v6, expected",
    [
        ((True, "0"), (True, "0"), STATUS_PASS),
        ((True, "0"), (False, ""), STATUS_PASS),
        ((True, "1"), (True, "0"), STATUS_CRITICAL),
        ((True, "0"), (True, "1"), STATUS_WARNING),
        ((False, ""), (True, "0"), STATUS_SKIPPED),
    ],
)
def test_accept_redirects_combines_ipv4_and_ipv6(monkeypatch, v4, v6, expected):
    _sysctl(monkeypatch, per_key={"net.ipv4.conf.all.accept_redirects": v4, "net.ipv6.conf.all.accept_redirects": v6})
    assert checks_kernel._check_accept_redirects()["status"] == expected


@pytest.mark.parametrize(
    "fn, good, bad",
    [
        (checks_kernel._check_syncookies, "1", "0"),
        (checks_kernel._check_dmesg_restrict, "1", "0"),
        (checks_kernel._check_tcp_rfc1337, "1", "0"),
        (checks_kernel._check_protected_hardlinks, "1", "0"),
        (checks_kernel._check_protected_symlinks, "1", "0"),
        (checks_kernel._check_aslr, "2", "0"),
        (checks_kernel._check_kptr_restrict, "2", "0"),
        (checks_kernel._check_bpf_jit_harden, "2", "0"),
        (checks_kernel._check_unprivileged_bpf, "1", "0"),
        (checks_kernel._check_ptrace_scope, "1", "0"),
        (checks_kernel._check_send_redirects, "0", "1"),
        (checks_kernel._check_source_route, "0", "1"),
        (checks_kernel._check_secure_redirects, "0", "1"),
    ],
    ids=lambda v: getattr(v, "__name__", v),
)
def test_recommended_value_passes_and_the_insecure_one_does_not(monkeypatch, fn, good, bad):
    monkeypatch.setattr(checks_kernel, "_is_container_or_multihomed", lambda: False)
    _sysctl(monkeypatch, good)
    assert fn()["status"] == STATUS_PASS
    _sysctl(monkeypatch, bad)
    assert fn()["status"] in (STATUS_WARNING, STATUS_CRITICAL)


# ---- host type detection ------------------------------------------------------------------------------------------


class Host:
    """A fake host for _is_container_or_multihomed: directories, binaries and `ip` output."""

    def __init__(self, dirs=(), binaries=(), default_routes="", addr="", routes=""):
        self.dirs, self.binaries = set(dirs), set(binaries)
        self.outputs = {
            ("ip", "route", "show", "default"): default_routes,
            ("ip", "-o", "-4", "addr", "show"): addr,
            ("ip", "-o", "-4", "route", "show"): routes,
        }

    def isdir(self, path):
        return path in self.dirs

    def run(self, args, timeout=None):
        args = list(args)
        if args[0] == "which":
            return CmdResult(0 if args[1] in self.binaries else 1, "", "")
        key = tuple(args)
        if key in self.outputs:
            return CmdResult(0, self.outputs[key], "")
        return CmdResult(1, "", "")


def _host(monkeypatch, **kwargs):
    host = Host(**kwargs)
    monkeypatch.setattr(checks_kernel.os.path, "isdir", host.isdir)
    monkeypatch.setattr(checks_kernel, "run_cmd", host.run)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"dirs": {"/var/lib/docker"}},
        {"binaries": {"docker"}},
        {"dirs": {"/etc/kubernetes"}},
        {"binaries": {"kubelet"}},
        {"dirs": {"/etc/wireguard"}},
        {"binaries": {"wg"}},
        {"default_routes": "default via 10.0.0.1 dev eth0\ndefault via 192.168.1.1 dev eth1\n"},
        {
            "addr": "2: eth0    inet 10.0.0.5/24\n3: eth1    inet 192.168.1.5/24\n",
            "routes": "10.1.0.0/16 via 10.0.0.1 dev eth0\n10.2.0.0/16 via 192.168.1.1 dev eth1\n",
        },
    ],
    ids=["docker-dir", "docker-bin", "k8s-dir", "kubelet", "wg-dir", "wg-bin", "two-default-routes", "two-gateways"],
)
def test_container_or_multihomed_hosts_are_detected(monkeypatch, kwargs):
    _host(monkeypatch, **kwargs)
    assert checks_kernel._is_container_or_multihomed() is True


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {"default_routes": "default via 10.0.0.1 dev eth0\n"},
        {
            "addr": "1: lo    inet 127.0.0.1/8\n2: eth0    inet 10.0.0.5/24\n",
            "routes": "default via 10.0.0.1 dev eth0\nbroken\nvia\n",
        },
    ],
    ids=["bare", "single-default-route", "single-gateway"],
)
def test_plain_hosts_are_not_container_hosts(monkeypatch, kwargs):
    _host(monkeypatch, **kwargs)
    assert checks_kernel._is_container_or_multihomed() is False


def test_read_sysctl_parses_the_command_output(monkeypatch):
    monkeypatch.setattr(checks_kernel, "run_cmd", lambda args, timeout=None: CmdResult(0, " 2\n", ""))
    assert checks_kernel._read_sysctl("kernel.randomize_va_space") == (True, "2")
    monkeypatch.setattr(checks_kernel, "run_cmd", lambda args, timeout=None: CmdResult(255, "", "unknown key"))
    assert checks_kernel._read_sysctl("nope") == (False, "")
