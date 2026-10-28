import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_llm as L

_PAYLOAD = {"data": [
    {"id": "vendor/big:free"}, {"id": "vendor/small:free"}, {"id": "vendor/paid"},
]}


def test_filters_free_only(tmp_path):
    got = L.discover_openrouter_models("k", allow_paid=False,
                                       cache_path=tmp_path / "c.json",
                                       _fetch=lambda key: _PAYLOAD)
    assert got == ["vendor/big:free", "vendor/small:free"]


def test_allow_paid_includes_all(tmp_path):
    got = L.discover_openrouter_models("k", allow_paid=True,
                                       cache_path=tmp_path / "c.json",
                                       _fetch=lambda key: _PAYLOAD)
    assert "vendor/paid" in got


def test_cache_hit_skips_fetch(tmp_path):
    cache = tmp_path / "c.json"
    cache.write_text(json.dumps({"ts": 1000.0, "models": ["cached:free"]}))
    calls = []
    got = L.discover_openrouter_models("k", cache_path=cache, ttl=3600,
                                       _now=lambda: 1100.0,
                                       _fetch=lambda key: calls.append(1) or _PAYLOAD)
    assert got == ["cached:free"] and not calls
