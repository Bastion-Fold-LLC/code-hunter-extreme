#!/usr/bin/env python3
"""Phase 1: YWH pagination loop + Bugcrowd Managed-field demotion."""

import json

import oracle_programs as op


def _ywh_items(n, tag):
    return [
        {"slug": f"prog-{tag}-{i}", "name": f"Prog {tag} {i}", "max_bounty": 1000}
        for i in range(n)
    ]


def test_ywh_paginates_until_short_page(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if "page=1&" in url:
            return json.dumps({"items": _ywh_items(100, "p1")})
        if "page=2&" in url:
            return json.dumps({"items": _ywh_items(3, "p2")})
        raise AssertionError(f"unexpected page fetch: {url}")

    monkeypatch.setattr(op, "_get", fake_get)
    monkeypatch.setattr(op.time, "sleep", lambda s: None)
    progs = op._scrape_yeswehack()
    assert len(progs) == 103
    assert len(calls) == 2


def test_ywh_stops_on_empty(monkeypatch):
    monkeypatch.setattr(op, "_get", lambda url, **kw: json.dumps({"items": []}))
    assert op._scrape_yeswehack() == []


def test_ywh_respects_page_cap(monkeypatch):
    monkeypatch.setattr(
        op, "_get", lambda url, **kw: json.dumps({"items": _ywh_items(100, "x")})
    )
    monkeypatch.setattr(op.time, "sleep", lambda s: None)
    assert len(op._scrape_yeswehack()) == 2000  # 20 pages x 100


def test_bugcrowd_managed_fields_not_name(monkeypatch):
    payload = json.dumps(
        {
            "engagements": [
                {"name": "Managed Foo Program", "briefUrl": "/a"},
                {"name": "Plain", "briefUrl": "/b", "managed_services": True},
                {"name": "Other", "briefUrl": "/c", "serviceLevel": "Managed"},
                {"name": "VDP", "briefUrl": "/d"},
            ]
        }
    )
    monkeypatch.setattr(op, "_session_get", lambda *a, **k: payload)
    monkeypatch.setattr(op.time, "sleep", lambda s: None)
    progs = {p["name"]: p for p in op._scrape_bugcrowd()}
    assert not progs["Managed Foo Program"]["fast_triage"]
    assert progs["Plain"]["fast_triage"]
    assert progs["Other"]["fast_triage"]
    assert not progs["VDP"]["fast_triage"]
