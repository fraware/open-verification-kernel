from ovk.core.pr_comment import OVK_COMMENT_MARKER, find_existing_ovk_comment, with_ovk_marker


def test_with_ovk_marker_adds_marker() -> None:
    rendered = with_ovk_marker("## Open Verification Kernel\n")
    assert rendered.startswith(OVK_COMMENT_MARKER)


def test_with_ovk_marker_is_idempotent() -> None:
    text = f"{OVK_COMMENT_MARKER}\n\nbody"
    assert with_ovk_marker(text) == text


def test_find_existing_ovk_comment_returns_matching_id() -> None:
    comments = [
        {"id": 1, "body": "other"},
        {"id": 2, "body": f"{OVK_COMMENT_MARKER}\n\nreport"},
    ]
    assert find_existing_ovk_comment(comments) == 2


def test_find_existing_ovk_comment_returns_none_without_match() -> None:
    assert find_existing_ovk_comment([{"id": 1, "body": "other"}]) is None
