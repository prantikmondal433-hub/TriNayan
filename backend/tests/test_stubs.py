import asyncio

import pytest

from app import community
from app.modules import cert, threat, websec
from app.schemas import ModuleResult, ScanContext


@pytest.mark.parametrize("mod,name", [
    (threat, "threat"),
    (websec, "websec"),
    (cert, "cert"),
    (community, "community"),
])
def test_stub_returns_valid_result(mod, name):
    result = asyncio.run(mod.analyze("https://example.com", ScanContext()))
    assert isinstance(result, ModuleResult)
    assert result.module == name
    assert 0 <= result.score <= 100