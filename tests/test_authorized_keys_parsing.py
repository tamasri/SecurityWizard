"""authorized_keys parsing with real SSH wire-format blobs (options with spaces, key sizes, fingerprints)."""

import base64
import hashlib

import checks_access
from checks_access import _check_authorized_keys, _derive_bits, _line_restrictions, _parse_key_line, split_key_line
from common import STATUS_INFO, STATUS_WARNING


def _string(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def _ed25519_blob() -> bytes:
    return _string(b"ssh-ed25519") + _string(bytes(range(32)))


def _rsa_blob(bits: int) -> bytes:
    modulus = (1 << (bits - 1)) | 1  # exactly `bits` bits long
    n = modulus.to_bytes((bits + 7) // 8 + 1, "big")  # mpint keeps a leading zero byte
    return _string(b"ssh-rsa") + _string((65537).to_bytes(3, "big")) + _string(n)


def _line(blob: bytes, key_type: str, options: str = "", comment: str = "host") -> str:
    key = base64.b64encode(blob).decode()
    return " ".join(part for part in (options, key_type, key, comment) if part)


def test_forced_command_key_with_spaces_in_the_options_is_restricted():
    line = _line(
        _ed25519_blob(),
        "ssh-ed25519",
        'command="/usr/bin/rsync --server --sender -logDtpre.iLsfxC . /srv/data",no-pty,no-port-forwarding',
    )
    assert split_key_line(line)[1] == "ssh-ed25519"
    restrictions = _line_restrictions(line)
    assert any(r.startswith("command=") for r in restrictions)
    assert "no-pty" in restrictions and "no-port-forwarding" in restrictions
    [result] = _check_authorized_keys(line, {})
    assert result["status"] == STATUS_INFO  # a deploy key is legitimate, not an unrestricted root key


def test_plain_restrict_option_counts_as_restricted():
    line = _line(_ed25519_blob(), "ssh-ed25519", "restrict")
    assert _line_restrictions(line) == ["restrict"]
    [result] = _check_authorized_keys(line, {})
    assert result["status"] == STATUS_INFO


def test_unrestricted_root_key_is_a_warning():
    [result] = _check_authorized_keys(_line(_ed25519_blob(), "ssh-ed25519"), {})
    assert result["status"] == STATUS_WARNING


def test_rsa_key_size_is_read_from_the_modulus():
    assert _derive_bits("ssh-rsa", _rsa_blob(2048)) == "2048"
    assert _derive_bits("ssh-rsa", _rsa_blob(4096)) == "4096"
    assert _derive_bits("ssh-rsa", b"garbage") == "unknown"


def test_small_rsa_keys_for_root_are_flagged_and_large_ones_are_not_flagged_as_weak():
    [small] = _check_authorized_keys(_line(_rsa_blob(2048), "ssh-rsa", "restrict"), {})
    [large] = _check_authorized_keys(_line(_rsa_blob(4096), "ssh-rsa", "restrict"), {})
    assert small["status"] == STATUS_WARNING
    assert large["status"] == STATUS_INFO


def test_fingerprint_uses_the_openssh_format():
    blob = _ed25519_blob()
    key_type, bits, fingerprint, comment = _parse_key_line(_line(blob, "ssh-ed25519", comment="deploy key one"))
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    assert (key_type, bits, fingerprint, comment) == ("ssh-ed25519", "256", expected, "deploy key one")


def test_comments_blank_lines_and_garbage_are_ignored():
    assert _parse_key_line("") is None
    assert _parse_key_line("# a comment") is None
    assert _parse_key_line("ssh-ed25519 !!!not-base64!!!") is None
    assert split_key_line("just some words") is None
    assert checks_access.split_key_line("ssh-ed25519") is None
