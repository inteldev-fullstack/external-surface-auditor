# External Surface Security Auditor

A local, scope-bound MVP for authorized security checks against customer-provided staging and lab targets. It reports DNS, TLS, HTTP configuration, and configured API health-path observations without reading response bodies or running exploit payloads.

## Current MVP

- Responsive browser interface, usable from a desktop or mobile browser when opened on the same machine.
- Python scan runner supported on Windows, macOS, and Linux.
- Exact approved-target allowlist; every target must be labeled `staging` or `lab`.
- DNS A/AAAA/CNAME/NS/MX inspection, pinned-address TCP connections, TLS certificate validation, and HEAD requests to `/` plus configured read-only health paths.
- Findings for TLS validation or near-expiry, missing HTTPS signals, selected security headers, and HTTP 5xx responses.
- JSON report export; scan results are not persisted by the server.

This is a local prototype. It does not yet provide accounts, multi-customer hosting, customer report portals, native Windows installers, a mobile application, production scans, or deeper authenticated application testing.

## Run on Windows

1. Install Python 3.11 or newer.
2. From this directory, create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```

3. Copy the example scope file and add only a customer-approved staging or lab asset:

   ```powershell
   Copy-Item config\approved_targets.example.json config\approved_targets.json
   ```

   Edit `config/approved_targets.json`. Example:

   ```json
   {
     "targets": [
       {
         "host": "staging.example.test",
         "environment": "staging",
         "paths": ["/health", "/api/health"],
         "allow_private": true
       }
     ]
   }
   ```

   Replace the example with an exact authorized hostname or IP. Use `allow_private: true` only for a specifically approved private test asset. Paths are sent as HEAD requests and must be read-only health endpoints.

4. Start the local server and open the browser UI:

   ```powershell
   python -m app.main
   ```

   Open `http://127.0.0.1:8765`.

## Run on macOS or Linux

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp config/approved_targets.example.json config/approved_targets.json
# Edit config/approved_targets.json to add an authorized staging/lab target.
python -m app.main
```

Open `http://127.0.0.1:8765` in a browser.

## Scope and network behavior

- The web server binds to `127.0.0.1`; do not expose it to a network.
- Only exact targets in `config/approved_targets.json` can be scanned. Wildcards, CIDRs, and arbitrary URLs are rejected.
- The MVP only scans entries marked `staging` or `lab`.
- Loopback, link-local, multicast, unspecified, and reserved addresses are blocked. Private addresses require an exact allowlist entry with `allow_private: true`.
- DNS answers are resolved once and pinned for HTTP connections. Redirects are summarized by scheme and hostname and are never followed.
- Each scan is sequential, uses short timeouts, scans one address, and requires 60 seconds before repeating a target.
- Checks use DNS queries and HTTP `HEAD` requests. They do not read bodies, access credentials, submit forms, make transactions, or run exploit payloads.
- The server keeps no scan history. The browser displays the current report and lets the operator download JSON.

## Report interpretation

Findings are observations for analyst review, not a claim that an asset is exploitable. Missing headers may be inappropriate for some applications; verify context before reporting. A network or TLS connection failure can indicate filtering or availability rather than a vulnerability.

## Roadmap

1. Scope review and audit history for a team deployment.
2. More web/API checks against isolated staging using customer-created test accounts and synthetic data.
3. Authenticated role-boundary checks and safer endpoint-specific reports.
4. Private-network runner for staging environments that cannot be reached from the public internet.
5. Customer report portal, team accounts, and a native mobile companion.

See [PLAN.md](PLAN.md) for the product plan and delivery boundaries.
