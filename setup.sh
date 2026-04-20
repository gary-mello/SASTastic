#!/usr/bin/env bash
set -e

echo "=== SASTastic Setup ==="
echo ""

# Python deps
echo "[1/9] Installing Python dependencies..."
pip install -r requirements.txt

# Semgrep
echo "[2/9] Installing Semgrep..."
pip install semgrep || echo "  WARN: semgrep install failed, skipping"

# Bandit
echo "[3/9] Installing Bandit..."
pip install bandit || echo "  WARN: bandit install failed, skipping"

# Checkov
echo "[4/9] Installing Checkov..."
pip install checkov || echo "  WARN: checkov install failed, skipping"

# Detect OS
OS="$(uname -s)"

# Gitleaks
echo "[5/9] Installing Gitleaks..."
if command -v brew &>/dev/null; then
  brew install gitleaks || echo "  WARN: gitleaks install failed"
elif [ "$OS" = "Linux" ]; then
  GITLEAKS_VER=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d'"' -f4)
  curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER#v}_linux_x64.tar.gz" | tar xz -C /usr/local/bin gitleaks || echo "  WARN: gitleaks install failed"
else
  echo "  INFO: Install gitleaks manually from https://github.com/gitleaks/gitleaks"
fi

# TruffleHog
echo "[6/9] Installing TruffleHog..."
if command -v brew &>/dev/null; then
  brew install trufflehog || echo "  WARN: trufflehog install failed"
elif [ "$OS" = "Linux" ]; then
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin || echo "  WARN: trufflehog install failed"
else
  echo "  INFO: Install trufflehog manually from https://github.com/trufflesecurity/trufflehog"
fi

# Hadolint
echo "[7/9] Installing Hadolint..."
if command -v brew &>/dev/null; then
  brew install hadolint || echo "  WARN: hadolint install failed"
elif [ "$OS" = "Linux" ]; then
  curl -sSL https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 -o /usr/local/bin/hadolint && chmod +x /usr/local/bin/hadolint || echo "  WARN: hadolint install failed"
else
  echo "  INFO: Install hadolint manually from https://github.com/hadolint/hadolint"
fi

# Gosec
echo "[8/9] Installing Gosec..."
if command -v go &>/dev/null; then
  go install github.com/securego/gosec/v2/cmd/gosec@latest || echo "  WARN: gosec install failed"
else
  echo "  INFO: go not found. Install Go then run: go install github.com/securego/gosec/v2/cmd/gosec@latest"
fi

# Brakeman
echo "[9/9] Installing Brakeman..."
if command -v gem &>/dev/null; then
  gem install brakeman || echo "  WARN: brakeman install failed"
else
  echo "  INFO: ruby/gem not found. Install Ruby then run: gem install brakeman"
fi

# Flawfinder
echo "[+] Installing Flawfinder..."
pip install flawfinder || echo "  WARN: flawfinder install failed"

echo ""
echo "=== Setup complete ==="
echo "Run: python app.py"
