"""Oracle enforcement red-team: deterministic challenger produces real verdicts."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import oracle_mindsets as om


def _seam(**over):
    base = {
        "n": 1,
        "mindset": "mitre",
        "assertion_a": "Auth is server-enforced",
        "assertion_b": "Wire returns data without creds",
        "check": "curl -s 'http://h.test/api/user/2'",
        "expected": "status 200",
        "severity": "high",
    }
    base.update(over)
    return base


def test_verifiable_card_confirmed():
    v = om.redteam_challenge([_seam()])
    assert v == {om.seam_candidate_key(_seam()): "confirmed"}


def test_identical_assertions_rejected():
    v = om.redteam_challenge([_seam(assertion_b="Auth is server-enforced")])
    assert set(v.values()) == {"rejected"}  # no binary conflict


def test_boundary_status_rejected():
    for status in ("status 401", "status 403", "status 530"):
        v = om.redteam_challenge([_seam(expected=status)])
        assert set(v.values()) == {"rejected"}, status


def test_out_of_scope_rejected():
    v = om.redteam_challenge([_seam()], in_scope=lambda url: False)
    assert set(v.values()) == {"rejected"}


def test_scope_oracle_failure_fails_closed_to_unreviewed():
    # Gate integrity: scope unknown => never "confirmed". Fail closed to
    # the honest neutral verdict; the wire verifier still decides.
    def boom(url):
        raise RuntimeError("gate blew up")

    v = om.redteam_challenge([_seam()], in_scope=boom)
    assert set(v.values()) == {"unreviewed"}


def test_unverifiable_card_unreviewed():
    v = om.redteam_challenge([_seam(check="", expected="")])
    assert set(v.values()) == {"unreviewed"}
    v2 = om.redteam_challenge([_seam(expected="body contains x")])  # no status
    assert set(v2.values()) == {"unreviewed"}


def test_code_seam_with_executed_output_confirmed():
    v = om.redteam_challenge(
        [
            _seam(
                check="forge test X",
                expected="",
                file="Vault.sol",
                function="withdraw",
                check_output="verdict CERTAIN",
            )
        ]
    )
    assert set(v.values()) == {"confirmed"}


def test_same_probe_twins_get_separate_verdicts():
    # S3: each lens's card is red-teamed on its own assertions. Same probe,
    # different cards must not merge into one verdict slot.
    good = _seam(mindset="paradox")
    bad = _seam(assertion_b="Auth is server-enforced")  # self-defeating twin
    assert om.seam_subject_key(good) == om.seam_subject_key(bad)
    assert om.seam_candidate_key(good) != om.seam_candidate_key(bad)
    v = om.redteam_challenge([good, bad])
    assert v[om.seam_candidate_key(good)] == "confirmed"
    assert v[om.seam_candidate_key(bad)] == "rejected"
    out = om.synthesize_seams(
        {"mitre": [bad], "paradox": [good]}, redteam_verdicts=v
    )
    assert len(out) == 2  # rank-only: rejected demotes, never drops
    by_mindset = {s["mindset"]: s["redteam_verdict"] for s in out}
    assert by_mindset == {"mitre": "rejected", "paradox": "confirmed"}


def test_challenge_by_lens_judges_each_lens_separately():
    good = _seam(mindset="paradox")
    bad = _seam(assertion_b="Auth is server-enforced")  # mitre twin
    weak = _seam(mindset="paradox", check="", expected="")
    verdicts, counts = om.redteam_challenge_by_lens([good, bad, weak])
    assert verdicts[om.seam_candidate_key(good)] == "confirmed"
    assert verdicts[om.seam_candidate_key(bad)] == "rejected"
    assert counts["mitre"] == {"confirmed": 0, "rejected": 1, "unreviewed": 0}
    assert counts["paradox"] == {"confirmed": 1, "rejected": 0, "unreviewed": 1}


def test_subject_keyed_verdicts_no_longer_apply():
    # Legacy pooled subject keys must not verdict both twins: synthesis
    # looks up per-candidate keys only (separate S3 gates).
    seam = _seam()
    out = om.synthesize_seams(
        {"mitre": [seam]},
        redteam_verdicts={om.seam_subject_key(seam): "rejected"},
    )
    assert out[0]["redteam_verdict"] == "unreviewed"


def test_synthesize_ranks_on_challenger_verdicts():
    weak = _seam(check="", expected="")  # unreviewed
    strong = _seam()  # confirmed
    verdicts = om.redteam_challenge([weak, strong])
    out = om.synthesize_seams(
        {"mitre": [weak], "paradox": [strong]}, redteam_verdicts=verdicts
    )
    assert out[0]["redteam_verdict"] == "confirmed"
    assert out[0]["check"] == strong["check"]
