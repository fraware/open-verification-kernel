#!/usr/bin/env bash
# Install a single OVK external backend binary for CI native-matrix jobs.
set -euo pipefail

BACKEND="${1:-}"
if [[ -z "${BACKEND}" ]]; then
  echo "usage: install_backend.sh <backend>"
  exit 1
fi

OPA_VERSION="0.67.0"
Z3_SOLVER_VERSION="4.13.4.0"
CBMC_APT_VERSION="6.4.1"

verify_binary() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "post-install check failed: ${name} not found on PATH"
    exit 1
  fi
  echo "post-install check: $(command -v "${name}")"
}

install_opa() {
  curl -fsSL -o opa "https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_amd64_static"
  chmod +x opa
  sudo mv opa /usr/local/bin/opa
  verify_binary opa
  opa version | grep -F "${OPA_VERSION}" >/dev/null
}

install_z3() {
  python -m pip install "z3-solver==${Z3_SOLVER_VERSION}"
  python - <<'PY'
import z3

version = z3.get_version_string()
expected = "4.13.4"
if not version.startswith(expected):
    raise SystemExit(f"post-install check failed: z3 version {version!r} does not start with {expected!r}")
print(f"post-install check: z3 {version}")
PY
}

install_cedar() {
  cargo install cedar-cli --locked 2>/dev/null || echo "cedar-cli install skipped (cargo unavailable)"
}

install_tla() {
  curl -fsSL -o tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
  sudo mkdir -p /opt/tla
  sudo mv tla2tools.jar /opt/tla/tla2tools.jar
  echo '#!/usr/bin/env bash' | sudo tee /usr/local/bin/tlc >/dev/null
  echo 'exec java -cp /opt/tla/tla2tools.jar tlc2.TLC "$@"' | sudo tee -a /usr/local/bin/tlc >/dev/null
  sudo chmod +x /usr/local/bin/tlc
}

install_kani() {
  cargo install kani-verifier --locked 2>/dev/null || echo "kani install skipped"
  cargo kani setup --yes 2>/dev/null || true
}

install_dafny() {
  curl -fsSL -o dafny.zip https://github.com/dafny-lang/dafny/releases/download/v4.8.0/dafny-4.8.0-x64-ubuntu-20.04.zip
  unzip -q dafny.zip
  sudo mv dafny /opt/dafny
  sudo ln -sf /opt/dafny/dafny /usr/local/bin/dafny
}

install_verus() {
  curl -fsSL -o verus.zip https://github.com/verus-lang/verus/releases/download/v0.2024.12.07/verus-x86-linux.zip
  unzip -q verus.zip
  sudo mv verus-x86-linux /opt/verus
  sudo ln -sf /opt/verus/verus /usr/local/bin/verus
}

install_lean() {
  curl -fsSL https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -o elan-init.sh
  bash elan-init.sh -y --default-toolchain stable
  echo "${HOME}/.elan/bin" >> "${GITHUB_PATH}"
}

install_cbmc() {
  sudo apt-get update -qq
  if ! sudo apt-get install -y -qq "cbmc=${CBMC_APT_VERSION}*" 2>/dev/null; then
    sudo apt-get install -y -qq cbmc
  fi
  verify_binary cbmc
  cbmc --version | grep -E "${CBMC_APT_VERSION%.*}" >/dev/null
}

install_alloy() {
  curl -fsSL -o alloy.jar https://repo1.maven.org/maven2/org/alloytools/alloy.dist/6.1.0/alloy.dist-6.1.0.jar
  sudo mkdir -p /opt/alloy
  sudo mv alloy.jar /opt/alloy/alloy.jar
  echo '#!/usr/bin/env bash' | sudo tee /usr/local/bin/alloy >/dev/null
  echo 'exec java -jar /opt/alloy/alloy.jar "$@"' | sudo tee -a /usr/local/bin/alloy >/dev/null
  sudo chmod +x /usr/local/bin/alloy
}

case "${BACKEND}" in
  opa) install_opa ;;
  z3) install_z3 ;;
  cedar) install_cedar ;;
  tla|tla+) install_tla ;;
  kani) install_kani ;;
  dafny) install_dafny ;;
  verus) install_verus ;;
  lean) install_lean ;;
  cbmc) install_cbmc ;;
  alloy) install_alloy ;;
  *)
    echo "unknown backend: ${BACKEND}"
    exit 1
    ;;
esac

echo "install_backend.sh: ${BACKEND} complete"
