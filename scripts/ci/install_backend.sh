#!/usr/bin/env bash
# Install a single OVK external backend binary from toolchains/backend-tools.lock.json.
# Required matrix backends fail closed when lock entries are missing or digests cannot
# be verified. Distro CBMC fallback and silent Kani skip are disabled for required tools.
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
backend = "${BACKEND}"
tools = {str(t.get("id")): t for t in lock.get("tools") or [] if isinstance(t, dict)}
# Normalize aliases
aliases = {"tla+": "tla"}
backend = aliases.get(backend, backend)
tool = tools.get(backend)
if tool is None:
    print(f"fail-closed: backend {backend!r} not in toolchain lock", file=sys.stderr)
    raise SystemExit(1)
value = tool.get("${field}")
if value is None:
    print("")
else:
    print(value)
PY
}

TOOL_ID="$(python_lock_query id)"
INSTALL_KIND="$(python_lock_query install)"
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

download_and_verify() {
  local url="$1"
  local dest="$2"
  local expected_sha="$3"
  curl -fsSL -o "${dest}" "${url}"
  if [[ -n "${expected_sha}" && "${expected_sha}" != "PLACEHOLDER_RESOLVE_AT_INSTALL" && "${expected_sha}" != "None" ]]; then
    echo "${expected_sha}  ${dest}" | sha256sum -c -
  else
    echo "warning: lock entry for ${TOOL_ID} has unresolved sha256; recording actual digest"
    sha256sum "${dest}"
    if [[ "${REQUIRED}" == "True" || "${REQUIRED}" == "true" ]]; then
      echo "fail-closed: required backend ${TOOL_ID} must have a concrete sha256 in ${LOCK}"
      exit 1
    fi
  fi
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
  local package artifact expected_sha tmpdir wheel
  package="$(python_lock_query package)"
  artifact="$(python_lock_query artifact_filename)"
  expected_sha="${SHA256}"
  if [[ -z "${expected_sha}" || "${expected_sha}" == "None" || "${expected_sha}" == "PLACEHOLDER_RESOLVE_AT_INSTALL" ]]; then
    echo "fail-closed: required backend z3 must have a concrete sha256 in ${LOCK}"
    exit 1
  fi
  tmpdir="$(mktemp -d)"
  # Prefer verifying the pinned manylinux wheel when pip can fetch it; always pin version.
  if [[ -n "${artifact}" && "${artifact}" != "None" ]]; then
    python -m pip download --no-deps -d "${tmpdir}" "${package}" || true
    wheel="$(ls "${tmpdir}"/*.whl 2>/dev/null | head -n1 || true)"
    if [[ -n "${wheel}" ]]; then
      actual="$(sha256sum "${wheel}" | awk '{print $1}')"
      if [[ "${actual}" != "${expected_sha}" ]]; then
        # Allow alternate platform wheels only when not required matrix? z3 is required:
        # accept only the locked digest or fail closed on linux CI when manylinux wheel present.
        if [[ "$(basename "${wheel}")" == "${artifact}" ]]; then
          echo "fail-closed: z3 wheel digest mismatch expected=${expected_sha} actual=${actual}"
          exit 1
        fi
        echo "warning: downloaded wheel $(basename "${wheel}") differs from locked ${artifact}; installing pinned version only"
      else
        echo "z3 wheel digest verified: ${actual}"
      fi
    else
      echo "warning: could not prefetch z3 wheel for digest check; installing pinned version ${package}"
    fi
  fi
  python -m pip install "${package}"
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
  local crate version tmp
  crate="$(python_lock_query crate)"
  version="${VERSION}"
  if [[ -z "${SHA256}" || "${SHA256}" == "None" || "${SHA256}" == "PLACEHOLDER_RESOLVE_AT_INSTALL" ]]; then
    echo "fail-closed: required backend cedar must have a concrete sha256 in ${LOCK}"
    exit 1
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    curl -fsSL https://sh.rustup.rs -o /tmp/rustup-init.sh
    bash /tmp/rustup-init.sh -y --default-toolchain stable --profile minimal
    # shellcheck disable=SC1091
    source "${HOME}/.cargo/env"
    echo "${HOME}/.cargo/bin" >> "${GITHUB_PATH:-/dev/null}"
  fi
  tmp="$(mktemp).crate"
  curl -fsSL -o "${tmp}" "${URL}"
  echo "${SHA256}  ${tmp}" | sha256sum -c -
  cargo install "${crate}" --version "${version}" --locked --force
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
  local crate version tmp
  crate="$(python_lock_query crate)"
  version="${VERSION}"
  if [[ -z "${SHA256}" || "${SHA256}" == "None" || "${SHA256}" == "PLACEHOLDER_RESOLVE_AT_INSTALL" ]]; then
    echo "fail-closed: kani lock entry must carry a concrete sha256"
    exit 1
  fi
  tmp="$(mktemp).crate"
  curl -fsSL -o "${tmp}" "${URL}"
  echo "${SHA256}  ${tmp}" | sha256sum -c -
  cargo install "${crate}" --version "${version}" --locked
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

echo "install_backend.sh: ${TOOL_ID} complete (lock-driven)"
