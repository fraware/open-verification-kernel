from benchmarks.formal_pr_bench.score_infra_exposure import main as score_infra_exposure


def test_infra_exposure_scorer_passes() -> None:
    assert score_infra_exposure() == 0
