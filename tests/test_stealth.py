import pytest
from pathlib import Path
from malforge import emit, crypt

def test_stealth_format_generation():
    # Test that 'stealth' format renders without error and contains key markers
    sc = b"\x90" * 100
    encrypted, meta = crypt.chain(sc, ["xor", "aes"])
    
    rendered = emit.render(
        "stealth", encrypted, meta,
        amsi=True, sandbox=True
    )
    
    # Check for D/Invoke and HWBP markers
    assert "_mfd" in rendered  # DInvoke class
    assert "_mfs" in rendered  # Stealth class (HWBP/VEH)
    assert "NtAl" in rendered # Concatenated in template
    assert "ProcessorCount" in rendered  # Sandbox check
    assert "_mfs.SetupBypass();" in rendered # The call
    assert "AddVectoredExceptionHandler" in rendered

def test_stealth_format_no_amsi():
    # Test that stealth format without amsi/etw flags doesn't include the bypass call
    sc = b"\x90" * 10
    encrypted, meta = crypt.chain(sc, [])
    
    rendered = emit.render(
        "stealth", encrypted, meta,
        amsi=False, etw=False
    )
    
    assert "_mfs.SetupBypass();" not in rendered
    # But classes should still be there for D/Invoke
    assert "_mfd" in rendered
