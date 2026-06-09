from ovk.core.exit_codes import exit_code_for_recommendation


def test_exit_code_for_allow() -> None:
    assert exit_code_for_recommendation("allow") == 0


def test_exit_code_for_block() -> None:
    assert exit_code_for_recommendation("block") == 1


def test_exit_code_for_review_and_unknown_recommendation() -> None:
    assert exit_code_for_recommendation("require_human_review") == 2
    assert exit_code_for_recommendation("unexpected") == 2
