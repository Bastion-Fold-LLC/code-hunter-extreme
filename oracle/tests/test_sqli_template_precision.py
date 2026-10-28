#!/usr/bin/env python3
"""G6 precision: the code-sqli template must not CERTAIN-mint identifier
interpolation (table/column names), only value-position interpolation.

Matomo rerun evidence (2026-10-27): 21 CERTAIN candidates, all teardown-
failed; sampled lines were internal table identifiers in backticks or
bound parameters. True positives that must keep firing: DVWA low.php,
Juice Shop login/search, PyGoat login (all value-position).

Line-level assertions go through _t_code_sqli_sink because scan-level
cards dedupe on the per-file grep check string.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import oracle_hunter as oh  # noqa: E402
import oracle_seam_templates as st  # noqa: E402

BASE = "http://127.0.0.1:55556"

IDENTIFIER_ONLY_PHP = """<?php
$sql   = 'SELECT option_value, option_name FROM `' . $table . '` WHERE autoload = 1';
$all = $db->fetchAll('SELECT * FROM `' . $tableName . '`');
$query = $this->db->query('SELECT * FROM `' . $this->table . '` WHERE name = ?', $this->name);
$sql2 = 'SELECT ' . $this->config['dataColumn'] . ' FROM `' . $this->config['name'] . '`';
$ids = Db::fetchAll('SELECT DISTINCT idsite FROM ' . $tableName);
$rows = Db::fetchAll('SELECT * FROM ' . $this->tablePrefixed);
$sql3 = 'SELECT idaction FROM `' . Common::prefixTable('log_action') . '` WHERE type = ?';
$r = Db::fetchOne('SELECT 1 FROM ' . $this->getTable() . $matchesRequest, [$p]);
$s = 'SELECT option_value FROM `' . Common::prefixTable('option') . '` WHERE option_name = ?' . $lock;
$sql4 = "SELECT $select FROM " . $this->makeFromStatement($from) . ' WHERE ' . $where;
$sql5 = 'SELECT * FROM t ORDER BY ' . $sort;
$sql6 = 'SELECT * FROM t WHERE `' . $col . '` = ?';
"""

VALUE_FILES = {
    "dvwa.php": """<?php
$query  = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
""",
    "concat.php": """<?php
$sql = 'SELECT idaction FROM log_action WHERE type = ' . $actionType . ' )';
""",
    "inlist.php": """<?php
$row = Db::fetchOne('SELECT idsite from log_visit where idsite in (' . $idSites . ') and visit > ?', $time);
""",
    "complex.php": """<?php
$q = "SELECT * FROM t WHERE x = {$y}";
""",
    "login.ts": "models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND deletedAt IS NULL`)\n",
    "search.ts": "models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%') AND deletedAt IS NULL)`)\n",
    "login.py": "sql_query = \"SELECT * FROM introduction_login WHERE user='\"+name+\"' AND password='\"+password+\"'\"\n",
}


def _sink_payloads(repo: Path):
    return st._t_code_sqli_sink({"repo": repo})


def test_identifier_only_interpolation_mints_nothing(tmp_path):
    (tmp_path / "ident.php").write_text(IDENTIFIER_ONLY_PHP)
    payloads = _sink_payloads(tmp_path)
    assert payloads == [], [(p["line_b"], p["check_output"]) for p in payloads]

    gate = oh.ProgramScopeGate({}, target_fallback=BASE)
    cards = st.scan_template_seams(repo_path=tmp_path, scope_gate=gate)
    sqli = [c for c in cards if c["claim_type"] == "code-sqli-raw-interpolation"]
    assert sqli == []


def test_value_interpolation_still_mints_certain(tmp_path):
    for name, text in VALUE_FILES.items():
        (tmp_path / name).write_text(text)
    payloads = _sink_payloads(tmp_path)
    hit_files = {Path(p["source_b"]).name for p in payloads}
    assert hit_files == set(VALUE_FILES), hit_files
    assert all(p["verdict"] == "CERTAIN" for p in payloads)

    gate = oh.ProgramScopeGate({}, target_fallback=BASE)
    cards = st.scan_template_seams(repo_path=tmp_path, scope_gate=gate)
    sqli = [c for c in cards if c["claim_type"] == "code-sqli-raw-interpolation"]
    card_files = {Path(c["source_b"]).name for c in sqli}
    assert card_files == set(VALUE_FILES), card_files
    assert all(c["verdict"] == "CERTAIN" for c in sqli)
