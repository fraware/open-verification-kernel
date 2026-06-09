from ovk.adapters.infra.normalize import SUPPORTED_INFRA_INPUT_FORMATS


def test_supported_infra_input_formats_are_deterministic() -> None:
    assert SUPPORTED_INFRA_INPUT_FORMATS == ("infra", "terraform", "kubernetes")
