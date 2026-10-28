"""Fold-ready headers: layer, destination, endpoints per module."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

LAYERS = ("find", "think", "seal")
DESTS = ("basilisk", "codecrusher", "vortex")

_HEADER_RE = re.compile(r"^# (LAYER|DEST|ENDPOINTS|TOPICS): (.*)$")


def _modules():
    mods = sorted(ROOT.glob("oracle_*.py"))
    scripts = ROOT / "scripts"
    if scripts.is_dir():
        mods += sorted(scripts.glob("*.py"))
    return mods


def _header(path: Path):
    fields = {}
    for line in path.read_text().splitlines()[:12]:
        m = _HEADER_RE.match(line)
        if m:
            fields[m.group(1)] = m.group(2).split("# noqa")[0].strip()
    return fields


def test_every_module_has_fold_header():
    mods = _modules()
    assert len(mods) == 36, f"module roster changed: {[m.name for m in mods]}"
    for mod in mods:
        fields = _header(mod)
        assert set(fields) == {
            "LAYER",
            "DEST",
            "ENDPOINTS",
            "TOPICS",
        }, f"{mod.name}: missing header fields, have {sorted(fields)}"
        assert fields["LAYER"] in LAYERS, f"{mod.name}: bad LAYER"
        assert fields["DEST"] in DESTS, f"{mod.name}: bad DEST"
        assert fields["ENDPOINTS"], f"{mod.name}: empty ENDPOINTS"
        assert fields["TOPICS"], f"{mod.name}: empty TOPICS"


def test_endpoints_resolve_to_definitions():
    for mod in _modules():
        fields = _header(mod)
        endpoints = fields.get("ENDPOINTS", "")
        if endpoints == "none":
            continue
        src = mod.read_text()
        for name in [e.strip() for e in endpoints.split(",")]:
            assert re.search(
                rf"^(def|class) {re.escape(name)}\b", src, re.MULTILINE
            ), f"{mod.name}: ENDPOINTS {name!r} has no def/class"
