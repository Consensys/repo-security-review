#!/usr/bin/env bash
# setup.sh — Install prerequisites for the security-review skill
# Run once before first use

set -e
echo "=== Security Review Skill — Prerequisite Setup ==="

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
  fi
}

install_pip_audit() {
  echo "Installing pip-audit (Python CVE scanning)..."
  if command -v pip3 &>/dev/null; then
    pip3 install pip-audit --break-system-packages 2>/dev/null || pip3 install pip-audit
  fi
}

# Required tools
command -v gitleaks &>/dev/null   && echo "✅ gitleaks: $(gitleaks version)"     || install_gitleaks
command -v osv-scanner &>/dev/null && echo "✅ osv-scanner installed"             || install_osv_scanner
command -v semgrep &>/dev/null    && echo "✅ semgrep: $(semgrep --version)"      || install_semgrep
command -v pip-audit &>/dev/null  && echo "✅ pip-audit installed"                || install_pip_audit

# Optional: Docker (for runtime validation)
echo ""
echo "=== Optional: Docker (for --runtime mode) ==="
if command -v docker &>/dev/null; then
  echo "✅ docker: $(docker --version)"
  if command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
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
echo ""
echo "Usage examples:"
echo "  /security-review /path/to/repo"
echo "  /security-review /path/to/repo --skip secrets,poc"
echo "  /security-review /path/to/repo --output ~/reports/myapp.md"
echo "  /security-review /path/to/repo --runtime --output ~/reports/myapp.md"
