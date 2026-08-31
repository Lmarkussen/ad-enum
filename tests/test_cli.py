import subprocess
import sys

from ad_enum.cli import _build_parser


def test_dc_ip_and_legacy_dc_flags_share_the_same_destination():
    common = ["-domain", "example.test", "-u", "scanuser"]
    canonical = _build_parser().parse_args([*common, "-dc-ip", "192.0.2.10"])
    legacy = _build_parser().parse_args([*common, "-dc", "192.0.2.10"])

    assert canonical.dc == "192.0.2.10"
    assert legacy.dc == canonical.dc


def test_help_presents_canonical_dc_ip_flag():
    result = subprocess.run([sys.executable, "ad-enum.py", "--help"],
                            capture_output=True, text=True, check=False)

    assert result.returncode == 0
    assert "-dc-ip DC_IP" in result.stdout
    assert "domain controller IP address" in result.stdout
