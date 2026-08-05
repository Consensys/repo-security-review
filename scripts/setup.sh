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

install_jq() {
  echo "Installing jq..."
  if command -v brew &>/dev/null; then
    brew install jq
  elif command -v apt-get &>/dev/null; then
    sudo apt-get install -y jq
  elif command -v yum &>/dev/null; then
    sudo yum install -y jq
  else
    LATEST=$(curl -s https://api.github.com/repos/jqlang/jq/releases/latest \
      | grep '"tag_name"' | cut -d'"' -f4)
    OS_RAW=$(uname -s | tr '[:upper:]' '[:lower:]' | sed 's/darwin/macos/')
    ARCH=$(uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')
    DEST="$HOME/.local/bin"
    mkdir -p "$DEST"
    curl -sSL \
      "https://github.com/jqlang/jq/releases/download/${LATEST}/jq-${OS_RAW}-${ARCH}" \
      -o "$DEST/jq" && chmod +x "$DEST/jq"
    echo "  ℹ️  jq installed to $DEST — ensure $DEST is in your PATH"
  fi
}

install_grype() {
  echo "Installing grype (Java/Maven CVE scanning)..."
  if command -v brew &>/dev/null; then
    brew install grype
  elif command -v go &>/dev/null; then
    go install github.com/anchore/grype/cmd/grype@latest
  else
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
      | sh -s -- -b "$HOME/.local/bin"
    echo "  ℹ️  grype installed to $HOME/.local/bin — ensure it is in your PATH"
  fi
}

install_poetry() {
  echo "Installing poetry (Python poetry.lock support)..."
  if command -v brew &>/dev/null; then
    brew install poetry
  elif command -v pip3 &>/dev/null; then
    pip3 install poetry --break-system-packages 2>/dev/null || pip3 install poetry
  else
    curl -sSL https://install.python-poetry.org | python3 -
    echo "  ℹ️  poetry installed — ensure ~/.local/bin is in your PATH"
  fi
}

# Core tools — failures are recorded but do not abort the script
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

if command -v jq &>/dev/null; then
  echo "✅ jq: $(jq --version)"
else
  try_install jq install_jq
fi

echo ""
echo "=== Optional: Language-specific tools ==="

# grype — Java/Maven CVE scanning (Phase 3); only needed for Java repos
if command -v grype &>/dev/null; then
  echo "✅ grype: $(grype version 2>/dev/null | head -1)"
else
  echo "ℹ️  grype not found — Java/Maven CVE scanning (Phase 3) will be skipped for Java repos"
  try_install grype install_grype
fi

# poetry — Python poetry.lock export (Phase 3); only needed for repos using poetry
if command -v poetry &>/dev/null; then
  echo "✅ poetry: $(poetry --version)"
else
  echo "ℹ️  poetry not found — poetry.lock CVE scanning will be skipped (requirements.txt still works)"
  try_install poetry install_poetry
fi

# Semgrep rule cache — download registry packs so scans don't depend on registry availability
# Packs are stored at $HOME/.config/repo-security-review/semgrep/<name>.yaml
# Phase 4 prefers these local files; falls back to the registry if a file is absent.
echo ""
echo "=== Semgrep rule cache ==="
SEMGREP_RULES_DIR="$HOME/.config/repo-security-review/semgrep"
mkdir -p "$SEMGREP_RULES_DIR"
echo "Cache directory: $SEMGREP_RULES_DIR"

download_semgrep_pack() {
  local pack=$1          # e.g. p/owasp-top-ten
  local name="${pack#p/}" # e.g. owasp-top-ten
  local dest="$SEMGREP_RULES_DIR/${name}.yaml"
  printf "  %-30s" "$pack"
  if curl -sSf "https://semgrep.dev/c/${pack}" -o "${dest}.tmp" 2>/dev/null \
     && mv "${dest}.tmp" "$dest"; then
    local count
    count=$(grep -c "^- id:\|^  id:" "$dest" 2>/dev/null || echo "?")
    echo "✅  cached (${count} rules)"
  else
    rm -f "${dest}.tmp"
    echo "⚠️  unavailable in registry — Phase 4 will probe at scan time"
  fi
}

echo "Core packs (always needed):"
for pack in p/owasp-top-ten p/security-audit; do
  download_semgrep_pack "$pack"
done

echo "Language packs:"
for pack in p/python p/golang p/javascript p/java p/ruby; do
  download_semgrep_pack "$pack"
done

echo "Security / framework packs:"
for pack in p/gosec p/django p/flask p/express p/react p/nodejs-scan p/ruby-security; do
  download_semgrep_pack "$pack"
done

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
      jq)          echo "   • jq:          https://jqlang.github.io/jq/download/ or: apt install jq" ;;
      grype)       echo "   • grype:       https://github.com/anchore/grype#installation" ;;
      poetry)      echo "   • poetry:      https://python-poetry.org/docs/#installation" ;;
    esac
  done
  echo "   Phases that depend on missing tools will run in degraded mode."
fi

echo ""
echo "Usage examples:"
echo "  /repo-security-review /path/to/repo"
echo "  /repo-security-review /path/to/repo --skip secrets,validation"
echo "  /repo-security-review /path/to/repo --output ~/reports/myapp"
echo "  /repo-security-review /path/to/repo --runtime --output ~/reports/myapp"
echo "  /repo-security-review --repos /path/svc1,/path/svc2,/path/svc3 --output ~/reports/my-system"
