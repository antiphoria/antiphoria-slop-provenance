# Quickstart: clone → tests → CLI

The software must be used in a research setting only.

This tooling is **experimental**. Do not rely on it for regulated or high-stakes decisions without appropriate legal and operational review. See [TERMS_OF_USE.md](TERMS_OF_USE.md) and [DISCLAIMER.md](DISCLAIMER.md).

Python **3.12** is the version used in CI; 3.10+ is supported per `pyproject.toml`.

## 1. Clone

```bash
git clone <repository-url>
cd slop-orchestrator-v0.0.1
```

## 2. Virtual environment

```bash
python3.12 -m venv .venv
source .venv/bin/activate          # Linux / macOS / WSL
# Windows (PowerShell):  .venv\Scripts\Activate.ps1
```

## 3. Install (app + test tooling)

```bash
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

Optional: OpenTimestamps support — `pip install -e ".[ots]"`.

## 4. Platform notes

- **Linux / macOS / WSL:** Native install is the supported path for development.
- **Windows without WSL:** Native builds (`liboqs-python`, OpenSSL) are fragile; use **WSL2** — see [WSL2_SETUP.md](WSL2_SETUP.md).

## 5. Environment (`.env`)

```bash
cp .env.example .env
```

Use **one** of the tracks below. All variables are documented in [`.env.example`](../.env.example).

### Track A — First green run (no Gemini, no Supabase)

Goal: run **`pytest`** and basic **`slop-cli`** without API keys or cloud services.

1. **ML-DSA keypair** (writes `keys/private.key` and `keys/public.key` under the repo — the `keys/` directory is gitignored at repo root):

   ```bash
   python scripts/gen-mldsa-keys.py
   ```

2. **Ed25519 keypair** (hybrid signing alongside ML-DSA):

   ```bash
   python scripts/gen-ed25519-keys.py
   ```

   This creates `keys/ed25519_private.pem` and `keys/ed25519_public.pem`. Adjust `.env` to point `ED25519_PRIVATE_KEY_PATH` and `ED25519_PUBLIC_KEY_PATH` at these files (paths can be relative to the project root).

3. In `.env`, set at least:

   - `GENERATOR_DUMMY_MODE=true` (and optionally `GENERATOR_DUMMY_DELAY_SEC=0`)
   - `PQC_PRIVATE_KEY_PATH` → `./keys/private.key` (or absolute path)
   - `OQS_PUBLIC_KEY_PATH` → `./keys/public.key`
   - `ED25519_PRIVATE_KEY_PATH` / `ED25519_PUBLIC_KEY_PATH` → your generated PEM paths
   - Leave **`TRANSPARENCY_LOG_PUBLISH_URL` empty** unless you use Supabase (Track B).

4. **Ledger:** the CLI expects `--repo-path` to be a **git repository**. Example:

   ```bash
   mkdir -p ../my-ledger && cd ../my-ledger && git init && cd -
   ```

### Track B — Full stack (Gemini + optional transparency)

1. Set `GENERATOR_DUMMY_MODE=false` and add **`GOOGLE_API_KEY`** (see `.env.example`).
2. If you set **`TRANSPARENCY_LOG_PUBLISH_URL`**, you **must** set **`SUPABASE_SERVICE_KEY`** or **`SUPABASE_ANON_KEY`** (CLI fails fast otherwise).
3. Configure RFC3161/TSA paths if you rely on timestamping; see `.env.example`.

### Production / vault (BYOV)

Do not rely on long-lived private keys on disk. Use the launchers and procedures in [SECURITY.md](SECURITY.md):

```bash
# Windows (PowerShell as Administrator)
./scripts/run-secure.ps1 slop-cli generate --prompt "..." --repo-path ../my-ledger

# Linux
./scripts/run-secure.sh slop-cli generate --prompt "..." --repo-path ../my-ledger
```

Further reading: [KEY_MANAGEMENT_POLICY.md](KEY_MANAGEMENT_POLICY.md).

## 6. Tests

```bash
pytest
# or: make test   (requires `make`; on Windows use WSL or install make)
```

## 7. CLI usage

After install, `slop-cli` is on your `PATH` (or use `python -m src.cli`).

```bash
slop-cli generate --prompt "A short story." --repo-path ../my-ledger
# Then run the printed attest command, or:
slop-cli verify --file ../my-ledger/<request_id>.md
```

More commands: root [README.md](../README.md).

## Optional: lint

With dev tooling installed, Ruff is available if you added it via `pip install -e ".[dev]"` (includes `ruff`):

```bash
make lint
```

Or: `ruff check .` and `ruff format .` from the project root.
