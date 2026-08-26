#!/usr/bin/env bash
# Install a single external backend from toolchains/backend-tools.lock.json.
# Required tools fail closed unless the installed artifact is the exact artifact
# whose immutable digest is recorded in the lock.
set -euo pipefail

BACKEND="${1:-}"
if [[ -z "${BACKEND}" ]]; then
  echo "usage: install_backend.sh <backend>"
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCK="${ROOT}/toolchains/backend-tools.lock.json"
if [[ ! -f "${LOCK}" ]]; then
  echo "fail-closed: missing toolchain lock ${LOCK}"
  exit 1
fi

python_lock_query() {
  local field="$1"
  python - <<PY
import json, sys
from pathlib import Path
lock = json.loads(Path(r"${LOCK}").read_text(encoding="utf-8"))
backend = {"tla+": "tla"}.get("${BACKEND}", "${BACKEND}")
tools = {str(t.get("id")): t for t in lock.get("tools") or [] if isinstance(t, dict)}
tool = tools.get(backend)
if tool is None:
    print(f"fail-closed: backend {backend!r} not in toolchain lock", file=sys.stderr)
    raise SystemExit(1)
value = tool.get("${field}")
print("" if value is None else value)
PY
}

TOOL_ID="$(python_lock_query id)"
VERSION="$(python_lock_query version)"
URL="$(python_lock_query url)"
SHA256="$(python_lock_query sha256)"
EXPECTED="$(python_lock_query expected_version_substr)"
ALLOW_DISTRO="$(python_lock_query allow_distro_fallback)"
ALLOW_SKIP="$(python_lock_query allow_silent_skip)"
REQUIRED="$(python_lock_query required_for_native_matrix)"

verify_binary() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "post-install check failed: ${name} not found on PATH"
    exit 1
  fi
  echo "post-install check: $(command -v "${name}")"
}

require_concrete_sha() {
  if [[ -z "${SHA256}" || "${SHA256}" == "None" || "${SHA256}" == "PLACEHOLDER_RESOLVE_AT_INSTALL" ]]; then
    echo "fail-closed: backend ${TOOL_ID} must have a concrete sha256 in ${LOCK}"
    exit 1
  fi
}

download_and_verify() {
  local url="$1"
  local dest="$2"
  local expected_sha="$3"
  curl --retry 3 --retry-all-errors -A "ovk-backend-installer/1.3" -fsSL -o "${dest}" "${url}"
  if [[ -n "${expected_sha}" && "${expected_sha}" != "PLACEHOLDER_RESOLVE_AT_INSTALL" && "${expected_sha}" != "None" ]]; then
    echo "${expected_sha}  ${dest}" | sha256sum -c -
  else
    sha256sum "${dest}"
    if [[ "${REQUIRED}" == "True" || "${REQUIRED}" == "true" ]]; then
      echo "fail-closed: required backend ${TOOL_ID} must have a concrete sha256 in ${LOCK}"
      exit 1
    fi
  fi
}

install_verified_crate() {
  local crate="$1"
  local version="$2"
  local tmp srcdir package_root
  require_concrete_sha
  tmp="$(mktemp).crate"
  srcdir="$(mktemp -d)"
  download_and_verify "${URL}" "${tmp}" "${SHA256}"
  tar -xzf "${tmp}" -C "${srcdir}"
  package_root="${srcdir}/${crate}-${version}"
  if [[ ! -f "${package_root}/Cargo.toml" ]]; then
    echo "fail-closed: verified crate did not contain expected package root ${crate}-${version}"
    exit 1
  fi
  cargo install --path "${package_root}" --locked --force
}

install_opa() {
  local tmp
  tmp="$(mktemp)"
  download_and_verify "${URL}" "${tmp}" "${SHA256}"
  chmod +x "${tmp}"
  sudo mv "${tmp}" /usr/local/bin/opa
  verify_binary opa
  opa version | grep -F "${EXPECTED}" >/dev/null
}

install_z3() {
  local package artifact tmpdir wheel actual
  package="$(python_lock_query package)"
  artifact="$(python_lock_query artifact_filename)"
  require_concrete_sha
  if [[ -z "${artifact}" || "${artifact}" == "None" ]]; then
    echo "fail-closed: z3 lock entry must name the exact wheel artifact"
    exit 1
  fi
  tmpdir="$(mktemp -d)"
  python -m pip download --only-binary=:all: --no-deps -d "${tmpdir}" "${package}"
  wheel="${tmpdir}/${artifact}"
  if [[ ! -f "${wheel}" ]]; then
    echo "fail-closed: resolved z3 wheel does not match locked artifact ${artifact}"
    find "${tmpdir}" -maxdepth 1 -type f -print
    exit 1
  fi
  actual="$(sha256sum "${wheel}" | awk '{print $1}')"
  if [[ "${actual}" != "${SHA256}" ]]; then
    echo "fail-closed: z3 wheel digest mismatch expected=${SHA256} actual=${actual}"
    exit 1
  fi
  python -m pip install "${wheel}"
  python - <<PY
import z3
version = z3.get_version_string()
expected = "${EXPECTED}"
if not version.startswith(expected):
    raise SystemExit(f"post-install check failed: z3 version {version!r} does not start with {expected!r}")
print(f"post-install check: z3 {version}")
PY
}

install_cedar() {
  local crate
  crate="$(python_lock_query crate)"
  if ! command -v cargo >/dev/null 2>&1; then
    curl --retry 3 --retry-all-errors -A "ovk-backend-installer/1.3" -fsSL https://sh.rustup.rs -o /tmp/rustup-init.sh
    bash /tmp/rustup-init.sh -y --default-toolchain stable --profile minimal
    # shellcheck disable=SC1091
    source "${HOME}/.cargo/env"
    echo "${HOME}/.cargo/bin" >> "${GITHUB_PATH:-/dev/null}"
  fi
  install_verified_crate "${crate}" "${VERSION}"
  if [[ -x "${HOME}/.cargo/bin/cedar" ]]; then
    sudo ln -sf "${HOME}/.cargo/bin/cedar" /usr/local/bin/cedar
  fi
  verify_binary cedar
  cedar --version | grep -F "${EXPECTED}" >/dev/null
}

install_kani() {
  if [[ "${ALLOW_SKIP}" == "True" || "${ALLOW_SKIP}" == "true" ]]; then
    echo "fail-closed: silent kani skip is disabled"
    exit 1
  fi
  local crate
  crate="$(python_lock_query crate)"
  install_verified_crate "${crate}" "${VERSION}"
  cargo kani setup --yes
  verify_binary cargo
}

install_cbmc() {
  if [[ "${ALLOW_DISTRO}" == "True" || "${ALLOW_DISTRO}" == "true" ]]; then
    echo "fail-closed: allow_distro_fallback must remain false for required CBMC"
    exit 1
  fi
  local tmp
  tmp="$(mktemp).deb"
  download_and_verify "${URL}" "${tmp}" "${SHA256}"
  sudo apt-get update -qq
  sudo apt-get install -y -qq "${tmp}"
  verify_binary cbmc
  cbmc --version | grep -F "${EXPECTED}" >/dev/null
}

install_tla() {
  local tmp
  tmp="$(mktemp).jar"
  download_and_verify "${URL}" "${tmp}" "${SHA256}"
  sudo mkdir -p /opt/tla
  sudo mv "${tmp}" /opt/tla/tla2tools.jar
  echo '#!/usr/bin/env bash' | sudo tee /usr/local/bin/tlc >/dev/null
  echo 'exec java -cp /opt/tla/tla2tools.jar tlc2.TLC "$@"' | sudo tee -a /usr/local/bin/tlc >/dev/null
  sudo chmod +x /usr/local/bin/tlc
  verify_binary tlc
}

case "${TOOL_ID}" in
  opa) install_opa ;;
  z3) install_z3 ;;
  cedar) install_cedar ;;
  cbmc) install_cbmc ;;
  tla) install_tla ;;
  kani) install_kani ;;
  *)
    echo "fail-closed: no lock-driven installer for ${TOOL_ID}"
    exit 1
    ;;
esac

echo "install_backend.sh: ${TOOL_ID} complete (lock-driven exact-artifact install)"
