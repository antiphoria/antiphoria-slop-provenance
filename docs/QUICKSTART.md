# Quickstart: clone → tests → CLI

The software must be used in a **research setting only** and **for artistic purposes**. This tooling is **experimental**—do not rely on it for regulated or high-stakes decisions without appropriate review. The CLI prompts once on first real use (not for `--help` only); for scripts or CI, set `ANTIPHORIA_SLOP_PROVENANCE_RESEARCH_ACK=1` after reading [TERMS_OF_USE.md](TERMS_OF_USE.md) and [DISCLAIMER.md](DISCLAIMER.md).

`pip install` does not show a separate legal screen; acknowledgment happens when you first run `slop-cli` (see above).

Python **3.12** is the version used in CI; 3.10+ is supported per `pyproject.toml`. Use a **project virtualenv** and that venv’s `python` / `pip` (not whatever `python` happens to be on your global PATH—e.g. a bleeding-edge install may lack `pygit2` wheels and break tests).

## 1. Clone

```bash
git clone <repository-url>
cd antiphoria-slop-provenance
```

## 2. Virtual environment

**Default (documented path):** create **`.venv`** at the repo root with Python 3.12.

```bash
python3.12 -m venv .venv
source .venv/bin/activate          # Linux / macOS / WSL
# Windows (PowerShell):  .venv\Scripts\Activate.ps1
```

**Optional:** a second local env dir **`.venv-freeze/`** (gitignored) is fine for a reproducible “pip freeze” layout. On Windows, `scripts/run-secure.ps1` prepends **`.venv-freeze\Scripts`** to `PATH` if it exists, otherwise **`.venv\Scripts`**, so `slop-cli` resolves from whichever you use—activate the same venv in your shell when running `pytest` or `python -m pip`.

## 3. Install (app + test tooling)

Recommended ([uv](https://docs.astral.sh/uv/)):

```bash
uv sync --extra dev
```

Alternative:

```bash
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

Optional: OpenTimestamps support — `pip install -e ".[ots]"`.

After install, the first non-`--help` `slop-cli` invocation may ask you to type `y` to confirm research/artistic use (unless `ANTIPHORIA_SLOP_PROVENANCE_RESEARCH_ACK=1` is set).

## 4. Platform notes

- **Linux / macOS / WSL:** Native install is the supported path for development.
- **Windows without WSL:** Native builds (`liboqs-python`, OpenSSL) are fragile; use **WSL2** — see [WSL2_SETUP.md](WSL2_SETUP.md).

## 5. Environment (`.env`)

```bash
cp .env.example .env
```

Use **one** of the tracks below. All variables are documented in [`.env.example`](../.env.example).

**Upgrade from `slop-orchestrator`:** use `ANTIPHORIA_SLOP_PROVENANCE_RESEARCH_ACK` (not `SLOP_ORCHESTRATOR_RESEARCH_ACK`). Config is under `%LOCALAPPDATA%\antiphoria-slop-provenance` or `~/.config/antiphoria-slop-provenance`; repo root lock file is `.antiphoria-slop-provenance.lock`. Re-run the first-run acknowledgment if you only had the old on-disk ack file.

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

   - `PQC_PRIVATE_KEY_PATH` → `./keys/private.key` (or absolute path)
   - `OQS_PUBLIC_KEY_PATH` → `./keys/public.key`
   - `ED25519_PRIVATE_KEY_PATH` / `ED25519_PUBLIC_KEY_PATH` → your generated PEM paths
   - (Optional) `RFC3161_TSA_URL` for trusted-third-party timestamping

4. **Ledger:** the CLI expects `--repo-path` to be a **git repository**. Example:

   ```bash
   mkdir -p ../my-ledger && cd ../my-ledger && git init && cd -
   ```

### Sealing content (v3)

v3 has two pipeline commands: `register` (human-authored, operator warrants) and `seal` (LLM-sourced, operator declares orchestration). Both are operator-side. Writers send text; they never install.

- `slop-cli seal --file <body.md> --models <m1>,<m2>` — seal operator-supplied LLM output.
- `slop-cli register --file <body.md>` — register a human-authored text.

The transparency log is local-only in v3 (Supabase remote publication removed); Bitcoin via OTS is the only remote anchor.

### Production / vault (BYOV)

Do not rely on long-lived private keys on disk. Use the launchers and procedures in [SECURITY.md](../SECURITY.md):

```bash
# Windows (PowerShell as Administrator)
./scripts/run-secure.ps1 slop-cli generate --prompt "..." --repo-path ../my-ledger

# Linux
./scripts/run-secure.sh slop-cli generate --prompt "..." --repo-path ../my-ledger
```

Further reading: [KEY_MANAGEMENT_POLICY.md](KEY_MANAGEMENT_POLICY.md).

### Track C — Human-only registration (Touch ID + pseudonym)

Goal: register **your own** markdown with maximum personhood metadata—without device fingerprinting.

1. Install WebAuthn support:

   ```bash
   pip install -e ".[webauthn]"
   ```

2. **Signing keys** — same as Track A or BYOV ([SECURITY.md](../SECURITY.md)): ML-DSA + Ed25519 paths in `.env`.

3. **Operator pseudonym salt** (optional, recommended for cross-artifact author continuity):

   ```bash
   python scripts/gen-pseudonym-salt.py --out /path/to/vault/pseudonym.salt
   ```

   In `.env`:

   ```bash
   OPERATOR_PSEUDONYM_SALT_PATH=/path/to/vault/pseudonym.salt
   ```

   The salt is secret; only `operatorPseudonymHash` (HMAC-SHA256) is embedded in artifacts. Do **not** set `CAPTURE_MACHINE_ID=true` if you want privacy-preserving personhood (MAC hashing is opt-in and discouraged for this workflow).

4. **macOS Touch ID** (platform provider):

   ```bash
   WEBAUTHN_PROVIDER=platform
   WEBAUTHN_RP_ID=antiphoria.org
   ```

   The ceremony runs on the hosted page `https://antiphoria.org/bridge.html`, which must be deployed before enrolling (the page origin must match `WEBAUTHN_RP_ID`). The CLI opens that page with the ceremony parameters in the URL fragment and runs a short-lived, loopback-only callback server; approve Touch ID when prompted. Omit `WEBAUTHN_BRIDGE_PORT` to use an ephemeral OS-assigned port (recommended). Set `WEBAUTHN_BRIDGE_URL` only to point at a staging page (must be https, or a loopback host for local testing).

   **USB security key** (default `hid` provider): set `WEBAUTHN_RP_ID` to your production domain, plug in a FIDO2 key, skip `WEBAUTHN_PROVIDER=platform`.

5. **One-time passkey enrollment** (before first register with WebAuthn):

   ```bash
   slop-cli webauthn-register --repo-path ../my-ledger
   ```

   Re-running enrollment is blocked while `.webauthn-credentials.json` exists in the ledger (delete that file and remove the macOS passkey in System Settings → Passwords to re-register).

6. **Register**:

   ```bash
   slop-cli register --file ./my-story.md --repo-path ../my-ledger
   ```

   Post-commit: transparency anchor and RFC3161 timestamp run automatically when configured (Track B). Follow with `slop-cli attest` for a full audit report.

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
