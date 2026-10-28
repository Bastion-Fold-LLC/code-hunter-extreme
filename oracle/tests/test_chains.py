"""Chain bridge + recon-artifact regression tests (connection trace).

DEAD #4: the hunt reflex task asked models for 'CHAINS INTO: SEAM [M]'
while _parse_seams only reads 'Chain output:' / 'Chain precondition:'
fields — LLM chain candidates could never populate. 5/23 templates
also had no _CHAIN_IO entry, so their cards could never form typed
edges.

DEAD #5 (partial): hakrawler overwrote js_endpoints.txt after JS
mining wrote it, clobbering mined endpoints instead of merging.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_hunter as oh
import oracle_seam_templates as st


def test_all_templates_have_chain_io():
    tids = [t["tid"] for t in st.TEMPLATES]
    missing = [t for t in tids if t not in st._CHAIN_IO]
    assert not missing, missing


def test_parse_seams_populates_chain_candidates():
    card = (
        "**SEAM 1**\n"
        "- Assertion A: policy says metrics internal (http://h.test/robots.txt)\n"
        "- Assertion B: metrics exposed at http://h.test/api\n"
        "- Reproducible check: `curl -i -s http://h.test/api`\n"
        "- Expected: status 200\n"
        "- Chain output: internal-host-7\n"
        "- Chain precondition: endpoint\n"
    )
    seams = oh._parse_seams(card)
    assert seams and seams[0]["chain_output_candidates"] == ["internal-host-7"]
    assert seams[0]["chain_preconditions"] == ["endpoint"]


def test_hunt_task_requests_parser_chain_format():
    src = (ROOT / "oracle_hunter.py").read_text(encoding="utf-8")
    assert "CHAINS INTO" not in src
    # Both task templates (run_reflexes + hunt reflex) request the
    # parser's field names.
    assert src.count("Chain output:") >= 2


def test_merge_line_file_unions_not_clobbers(tmp_path):
    p = tmp_path / "js_endpoints.txt"
    p.write_text("http://h.test/a.js\nhttp://h.test/b.js\n")
    n = oh._merge_line_file(p, "http://h.test/b.js\nhttp://h.test/c.js\n")
    lines = p.read_text().splitlines()
    assert n == 3
    assert lines == [
        "http://h.test/a.js",
        "http://h.test/b.js",
        "http://h.test/c.js",
    ]
