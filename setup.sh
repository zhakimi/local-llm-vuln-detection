#!/usr/bin/env bash
# amd-vuln-scanner setup: installs Ollama, pulls the model, installs Python deps.
# Everything runs locally; after this, no network access is needed to scan.
set -euo pipefail

MODEL="${AMD_SCANNER_MODEL:-llama3.2}"
OLLAMA_URL="${OLLAMA_HOST:-http://localhost:11434}"
[[ "$OLLAMA_URL" == http* ]] || OLLAMA_URL="http://$OLLAMA_URL"

ollama_up() { curl -fsS -m 2 "$OLLAMA_URL/api/tags" >/dev/null 2>&1; }

# 1. Install Ollama
if command -v ollama >/dev/null 2>&1; then
  echo "==> Ollama already installed ($(ollama --version 2>/dev/null | head -n1))"
else
  echo "==> Installing Ollama"
  curl -fsSL https://ollama.com/install.sh | sh
fi

# 2. Start the Ollama service in the background (skip if already running,
#    e.g. via the systemd service the installer creates)
if ollama_up; then
  echo "==> Ollama is already running at $OLLAMA_URL"
else
  echo "==> Starting Ollama in the background (log: /tmp/ollama-serve.log)"
  nohup ollama serve >/tmp/ollama-serve.log 2>&1 &
fi

# 3. Wait 3 seconds, then pull the model
sleep 3
for _ in $(seq 1 10); do ollama_up && break; sleep 1; done
ollama_up || { echo "Ollama did not start; see /tmp/ollama-serve.log" >&2; exit 1; }
echo "==> Pulling model: $MODEL"
ollama pull "$MODEL"

# 4. Install Python dependencies
echo "==> Installing Python dependencies"
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
  python3 -m pip install requests rich
else
  # Debian/Ubuntu block system-wide pip installs (PEP 668); fall back to --user.
  python3 -m pip install requests rich 2>/dev/null \
    || python3 -m pip install --user requests rich 2>/dev/null \
    || { echo "pip install was blocked. Create a venv first:  python3 -m venv .venv && source .venv/bin/activate && ./setup.sh" >&2; exit 1; }
fi

# 5. Done
echo "Setup complete. Run: python -m scanner scan ./sample_targets"
