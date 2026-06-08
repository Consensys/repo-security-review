#!/usr/bin/env bash
# setup.sh — Install prerequisites for the repo-security-review skill
# Run once before first use

echo "=== Security Review Skill — Prerequisite Setup ==="

FAILED=()

# Run an install function; record the tool name if it fails
try_install() {
  local cmd=$1
  local fn=$2
  if "$fn"; then
    return 0
  else
    FAILED+=("$cmd")
    echo "⚠️  $cmd install failed — install manually (see links below)"
    return 1
  fi
}

install_gitleaks() {
  echo "Installing gitleaks..."
  if command -v brew &>/dev/null; then
    brew install gitleaks
  elif command -v go &>/dev/null; then
    go install github.com/gitleaks/gitleaks/v8@latest
  else
    LATEST=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d'"' -f4)
    OS_LOWER=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m | sed 's/x86_64/x64/' | sed 's/aarch64/arm64/')
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/${LATEST}/gitleaks_${LATEST#v}_${OS_LOWER}_${ARCH}.tar.gz" \
      | tar xz -C /usr/local/bin gitleaks
  fi
}

install_osv_scanner() {
  echo "Installing osv-scanner..."
  if command -v brew &>/dev/null; then
    brew install osv-scanner
  elif command -v go &>/dev/null; then
    go install github.com/google/osv-scanner/cmd/osv-scanner@latest
  else
    echo "Please install osv-scanner manually: https://google.github.io/osv-scanner/installation/"
    return 1
  fi
}

install_semgrep() {
  echo "Installing semgrep..."
  if command -v pip3 &>/dev/null; then
    pip3 install semgrep --break-system-packages 2>/dev/null || pip3 install semgrep
  elif command -v brew &>/dev/null; then
    brew install semgrep
  else
    echo "Please install semgrep manually: https://semgrep.dev/docs/getting-started/"
    return 1
  fi
}

install_pip_audit() {
  echo "Installing pip-audit (Python CVE scanning)..."
  if command -v pip3 &>/dev/null; then
    pip3 install pip-audit --break-system-packages 2>/dev/null || pip3 install pip-audit
  else
    echo "Please install pip-audit manually: pip3 install pip-audit"
    return 1
  fi
}

# Required tools — failures are recorded but do not abort the script
if command -v gitleaks &>/dev/null; then
  echo "✅ gitleaks: $(gitleaks version)"
else
  try_install gitleaks install_gitleaks
fi

if command -v osv-scanner &>/dev/null; then
  echo "✅ osv-scanner installed"
else
  try_install osv-scanner install_osv_scanner
fi

if command -v semgrep &>/dev/null; then
  echo "✅ semgrep: $(semgrep --version)"
else
  try_install semgrep install_semgrep
fi

if command -v pip-audit &>/dev/null; then
  echo "✅ pip-audit installed"
else
  try_install pip-audit install_pip_audit
fi

# Optional: Docker (for runtime validation)
echo ""
echo "=== Optional: Docker (for --runtime mode) ==="
if command -v docker &>/dev/null; then
  echo "✅ docker: $(docker --version)"
  if docker compose version &>/dev/null 2>&1; then
    echo "✅ docker compose: $(docker compose version)"
  else
    echo "⚠️  docker compose not found — runtime validation may be limited"
  fi
else
  echo "⚠️  Docker not installed — runtime PoC validation (--runtime flag) will be unavailable"
  echo "   Install from: https://docs.docker.com/get-docker/"
fi

echo ""
echo "=== Setup complete ==="

if [ ${#FAILED[@]} -gt 0 ]; then
  echo ""
  echo "⚠️  The following tools could not be installed automatically:"
  for tool in "${FAILED[@]}"; do
    case "$tool" in
      gitleaks)    echo "   • gitleaks:    https://github.com/gitleaks/gitleaks#install" ;;
      osv-scanner) echo "   • osv-scanner: https://google.github.io/osv-scanner/installation/" ;;
      semgrep)     echo "   • semgrep:     https://semgrep.dev/docs/getting-started/" ;;
      pip-audit)   echo "   • pip-audit:   pip3 install pip-audit" ;;
    esac
  done
  echo "   Phases that depend on missing tools will run in degraded mode."
fi

echo ""
echo "Usage examples:"
echo "  /repo-security-review /path/to/repo"
echo "  /repo-security-review /path/to/repo --skip secrets,validation"
echo "  /repo-security-review /path/to/repo --output ~/reports/myapp.md"
echo "  /repo-security-review /path/to/repo --runtime --output ~/reports/myapp.md"
