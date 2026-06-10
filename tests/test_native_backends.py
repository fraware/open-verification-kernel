import pytest

from ovk.core.native_backend_probe import probe_native_backend


def _assert_backend(backend: str) -> None:
    results = probe_native_backend(backend)
    assert results, f"no probe results for backend {backend}"
    for result in results:
        assert result.runtime_status == result.oracle_status, (
            f"{backend} fixture {result.fixture_path} diverged from oracle: "
            f"runtime={result.runtime_status}, oracle={result.oracle_status}"
        )
        if result.binary_present:
            assert result.used_native_binary, (
                f"{backend} detected {result.binary_name} "
                "but did not report native use"
            )


@pytest.mark.native_backend(name="opa")
def test_native_backend_opa() -> None:
    _assert_backend("opa")


@pytest.mark.native_backend(name="z3")
def test_native_backend_z3() -> None:
    _assert_backend("z3")


@pytest.mark.native_backend(name="cedar")
def test_native_backend_cedar() -> None:
    _assert_backend("cedar")


@pytest.mark.native_backend(name="tla+")
def test_native_backend_tla() -> None:
    _assert_backend("tla+")


@pytest.mark.native_backend(name="kani")
def test_native_backend_kani() -> None:
    _assert_backend("kani")


@pytest.mark.native_backend(name="dafny")
def test_native_backend_dafny() -> None:
    _assert_backend("dafny")


@pytest.mark.native_backend(name="verus")
def test_native_backend_verus() -> None:
    _assert_backend("verus")


@pytest.mark.native_backend(name="lean")
def test_native_backend_lean() -> None:
    _assert_backend("lean")


@pytest.mark.native_backend(name="cbmc")
def test_native_backend_cbmc() -> None:
    _assert_backend("cbmc")


@pytest.mark.native_backend(name="alloy")
def test_native_backend_alloy() -> None:
    _assert_backend("alloy")
