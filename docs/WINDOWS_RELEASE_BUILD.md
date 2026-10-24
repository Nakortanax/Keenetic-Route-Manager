# Windows release build — 0.2.4

The tested GUI core remains version 0.2.4. Build a **Windows x64** PE file only on a trusted Windows x64 host. GitHub Actions must not be used for Windows builds.

## Build

Run `scripts/build_release_windows.cmd` on the trusted Windows x64 host with Python installed, or invoke `scripts/build_release_windows.ps1` from the local trusted Forgejo runner Windows step.

The script installs dependencies in .venv, runs all unit and GUI tests, runs PyInstaller, checks PE x64 architecture and builds `release/KeeneticRouteManager-0.2.4-Windows-x64.zip` with SHA-256.

## Local Forgejo integration (not yet configured)

Follow `CI_AUTOMATION_GUIDE_2026-10-19.md` from the owner's private Library. Add a **separate** Git Bridge timer for this new repo and a dedicated protected `ci/*` workflow in Forgejo. The trusted runner should verify the requested branch and exact source SHA before executing the Windows build script. Reuse the existing global Windows build lock; do not run arbitrary `bridge/*` workflow definitions on a privileged Windows runner.

The GitHub branch `bridge/windows-buildkit-v024-20261024` is only source/build tooling, **not** proof of a built EXE. An actual Windows run, SHA-256 validation and GUI smoke test are required before claiming a release artifact.

## Security

Never commit SSH private keys, router passwords, VPN keys, local route exports or activity logs. The application connects to Telnet (unencrypted), so use it only on a trusted LAN.
