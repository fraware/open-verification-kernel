from benchmarks.formal_pr_bench.score_authorization_obligation import main as score_authorization_obligation


def test_authorization_obligation_scorer_passes() -> None:
    assert score_authorization_obligation() == 0
