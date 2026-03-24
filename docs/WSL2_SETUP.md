# WSL2 setup (recommended on Windows)

Native Windows builds of `liboqs-python`, OpenSSL tooling, and `pygit2` are easy to get wrong. **WSL2 + Ubuntu** is the practical dev path.

## 1. Install WSL2 and Ubuntu

In an elevated PowerShell window:

```powershell
wsl --install
```

Reboot if prompted, then choose **Ubuntu** from the Start menu and create a UNIX user.

## 2. System packages (when wheels are not enough)

Most dependencies install via `pip`. If `liboqs-python` or `pygit2` fail to build, install build helpers:

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev pkg-config libgit2-1.1 libgit2-dev
```

(Exact `libgit2` package name can differ by Ubuntu version; `libgit2-dev` often pulls the right runtime.)

## 3. Python 3.12 in WSL

```bash
sudo apt install -y python3.12 python3.12-venv
```

If `python3.12` is not in your Ubuntu repos, use `deadsnakes` or `pyenv` — or align with the newest `python3` available and match CI in [.github/workflows/org-quality.yml](../.github/workflows/org-quality.yml) when possible.

## 4. Clone and install inside WSL

Work in the Linux filesystem (e.g. `~/projects/...`), not `/mnt/c/...`, for better file performance and fewer permission surprises:

```bash
cd ~
git clone <repository-url>
cd slop-orchestrator-v0.0.1
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[dev]"
```

## 5. Git and the ledger

Install Git if needed (`sudo apt install git`). Initialize ledger repos the same way as on Linux — see [QUICKSTART.md](QUICKSTART.md).

## 6. Docker Desktop (optional)

Docker Desktop can use WSL2 as the backend. That helps if you prefer containerized workflows; it is **not** required to develop this project in WSL. The repo [Dockerfile](../Dockerfile) is a separate, minimal entry point.

## 7. Next steps

Follow [QUICKSTART.md](QUICKSTART.md) for `.env`, keys, tests, and `slop-cli`.
