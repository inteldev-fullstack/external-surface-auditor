# External Surface Auditor

A standalone local security auditor for explicitly approved staging and lab domains/IPs. It checks external DNS, TLS, HTTP configuration and read-only health endpoints, then produces evidence-backed reports for analyst review.

## Version 1.2

- Customer workspaces on one computer, with targets, scan history and retest comparisons separated per workspace.
- Responsive web UI with target creation, editing and removal; no manual JSON editing required.
- Asynchronous scans with progress, cancellation and one active job at a time.
- DNS A/AAAA/CNAME/NS/MX resolution; validated IPs pinned for HTTP connections.
- TLS certificate validation, protocol, expiry and HTTPS response configuration.
- Sequential HEAD requests to the root and up to 10 explicitly approved health paths; timing and HTTP 5xx observations.
- Findings with severity, confidence, evidence and remediation guidance; search and severity filters.
- SQLite scan history on the local computer; export PDF, CSV or JSON; report deletion.
- Retest comparison with the previous completed assessment of the same target and exact scope. Missing observations do not prove remediation.
- Windows portable executable build, Windows source launch scripts, and Linux/macOS launcher.
- Regression tests and GitHub CI across Windows/Linux and Python 3.11–3.13.

## Windows: portable application

Download **ExternalSurfaceAuditor.exe** from [the v1.2.0 release](https://github.com/inteldev-fullstack/external-surface-auditor/releases/tag/v1.1.0). Launch it; the browser opens automatically at `http://127.0.0.1:8765`. Keep the application console open. No Python installation is required for the executable. The release workflow builds and smoke-tests this Windows executable before attaching it.

Packaged Windows data is stored under `%LOCALAPPDATA%\ExternalSurfaceAuditor\data\auditor.db`. It contains customer workspaces, approved targets and scan reports. The executable is not digitally signed. Windows CI verifies the portable build; individual customer networks and Windows configurations still need user acceptance testing.

## Windows: run from source

Install Python 3.11+ with its Python launcher. Download and extract the repository ZIP, or clone it:

```powershell
git clone https://github.com/inteldev-fullstack/external-surface-auditor.git
cd external-surface-auditor
.\install-windows.cmd
.\start-windows.cmd
```

You can also double-click the scripts. The installer creates a project-local Python environment; the launcher opens the UI after the service is ready. An existing running auditor is reused. A different service occupying port 8765 must be stopped first.

## Linux/macOS

Python 3.11+ with venv support is required:

```bash
git clone https://github.com/inteldev-fullstack/external-surface-auditor.git
cd external-surface-auditor
./start.sh
```

For a headless machine use `.venv/bin/python -m app.main` instead of the browser launcher.

## First assessment

1. Open `http://127.0.0.1:8765` on the same computer running the application.
2. Select **Add target**. Enter one exact authorized hostname or IP and choose staging or lab.
3. Add only known read-only health paths. Select private-network approval only for an approved private target. Confirm authorization and save.
4. Select the target, confirm current authorization and run checks.
5. Review progress and findings. Cancel if needed; cancellation takes effect between bounded DNS/socket operations.
6. Download PDF, CSV or JSON. After remediation, select **Retest** from history and run again. The latest identical-scope report is compared automatically.

The empty initial scope is intentional. No customer target is preconfigured and the example `.test` domain is not an operational service.

## Mobile report companion

Open `https://external-surface-auditor-mobile-preview.inteldev-manager.chatgpt.site` while signed into the Site owner's ChatGPT account, then save it to the phone home screen (Android browser: Install app; iPhone Safari: Share → Add to Home Screen). On the PC, export a scan as JSON and transfer that file to your phone using your approved private file-sharing method. In the PWA, choose the JSON report. Findings render locally, the page works offline after first load, and it does not upload or save report data. Clear the report before handing off the phone.

The companion is a private installable web app for report review. It cannot start scans; run scans from the Windows/desktop application.

## Local data and access

Source installs store customer workspaces, approved targets and report history in `data/auditor.db` inside the checkout. The database is ignored by Git. On upgrade, any legacy `config/approved_targets.json` entries migrate into the default workspace. Data is not encrypted by this application; protect the computer and its backups with your operating system's account and disk controls. The application does not upload reports or contact a telemetry service.

To use custom paths, set `ESA_SCOPE_FILE` to a scope JSON file or `ESA_DATA_DIR` to a database directory before launch. The source scope format is documented in `config/approved_targets.example.json`.

This release is a single-user local application. Its HTTP service binds only to `127.0.0.1`, accepts localhost Host headers and its own browser origins, rejects cross-site requests, and uses a restrictive content security policy. Do not publish this local API through a tunnel or bind it to a network interface. The mobile PWA at `/mobile/` imports JSON exports for private offline review. The phone viewer does not invoke the scan runner; scans still run on the Windows/desktop installation. The desktop app supports multiple local customer workspaces, but has no team logins: the Windows computer owner can access all workspaces.

## Check boundaries

- Exact approved staging/lab targets only; no production targets, wildcards, CIDR ranges or arbitrary URLs.
- All resolved addresses are validated. Loopback, link-local, multicast, unspecified and reserved IPs are rejected, including IPv4-mapped IPv6 variants. Private addresses require explicit per-target approval.
- One resolved address is scanned. DNS is pinned at scan start; HTTP redirects are recorded by scheme/hostname and never followed.
- Fixed HTTP/HTTPS ports 80/443; one active scan; 60-second per-target repeat delay per process; four-second connection timeouts and short DNS query limits.
- Only DNS lookups and HEAD requests; no crawling, brute force, credential testing, request bodies, transactions, exploit payloads, or application response bodies.
- Reported missing headers and connectivity failures require context. They are observations, not proof of exploitability. A cancelled job discards partial results. A stopped runner marks unfinished jobs interrupted on next startup.

The local confirmation is an operator declaration, not independent proof of domain ownership or customer authorization. Workspaces isolate local targets and reports by customer ID, but they are not a security boundary between Windows users. There are no team accounts, remote access, authenticated API roles or cloud scheduling.

## Development and validation

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m compileall -q app
node --check static/app.js
```

Tests use isolated temporary configuration/databases and mock network checks. They cover scope validation, special-address rejection, cancellation, local access boundaries, persistent job state, report exports, retest comparisons, CSV formula neutralization and TLS metadata when an HTTP connection closes. They do not scan third-party systems. GitHub runs the regression suite on Linux and Windows. The Windows release workflow also starts the packaged executable and checks its real HTTP service and static assets.

See [PLAN.md](PLAN.md) for longer-term team and native mobile platform plans.
