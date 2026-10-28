import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle_llm as L


def test_absent_file_returns_default():
    cfg = L.load_backend_config(Path("/nonexistent/oracle_backends.json"))
    assert cfg["routes"]["reflex"] == ["openrouter", "nvidia", "local"]


def test_local_disabled_strips_local_from_routes(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"local_enabled": False}))
    cfg = L.load_backend_config(p)
    assert all("local" not in r for r in cfg["routes"].values())


def test_file_overrides_merge(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"controller": "gemini"}))
    cfg = L.load_backend_config(p)
    assert cfg["controller"] == "gemini"
    assert "reflex" in cfg["routes"]  # default preserved


def test_project_routes_use_primary_then_fallbacks():
    cfg = L.load_backend_config()

    assert cfg["controller"] in ("groq", "databricks")
    assert cfg["local_model"] == "qwen3-coder:30b-16k"
    # Routes cascade through free tiers with local as ultimate fallback
    assert all(route[-1] == "local" for route in cfg["routes"].values())
    assert all("openrouter" in route and "nvidia" in route for route in cfg["routes"].values())
