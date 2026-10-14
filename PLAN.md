# External Surface Security Auditor

Product plan for a standalone tool that helps an authorized security team find and report externally reachable weaknesses in a customer's domain, IP, website, and API. The first release is intended for customer-provided test environments.

## Product goal

Reduce the time between receiving an approved target and giving the customer a useful, evidence-backed remediation report. The tool combines scoped external discovery with controlled web and API checks, and keeps each customer's assets and results isolated.

## Version 1.1 implementation status

Implemented: single-user local responsive web app, exact approved staging/lab target management, asynchronous scan jobs, status/cancellation, local SQLite history, DNS/TLS/HTTP HEAD checks, health paths, evidence and remediation, PDF/CSV/JSON reports, same-scope retest comparison, Windows launch scripts/portable executable workflow, a PWA for private offline mobile report review, and regression CI on Windows/Linux.

The executable is built and smoke-tested by the release workflow; the release assets and Actions runs provide its current verification status. Full team hosting, customer tenants, authentication/MFA, authenticated web/API assessments, remote workers, native mobile apps and customer portals below remain future milestones. This version is not an exhaustive vulnerability assessment.

## Intended users

- Security analyst: defines scope, configures a scan, reviews and validates findings.
- Team lead: approves scope and scan windows, reviews risk and reports.
- Customer contact: supplies authorized domains/IPs and test-environment access, receives findings and retest results.

## Operating assumptions

- Each customer supplies a written authorization and an explicit list of domains, IPs, and exclusions.
- Initial active scans run against isolated staging/test environments. Production scans are out of scope for the MVP.
- Customers provide synthetic test data and dedicated test accounts if authenticated checks are needed. No real player, payment, or customer data is required.
- Scan traffic is limited, attributable, logged, and constrained to the approved target list.
- The product reports evidence and remediation guidance; a human analyst reviews findings before delivery.

## MVP workflow

1. Create a customer workspace and record authorization details, contacts, validity dates, and scan exclusions.
2. Add domains/IPs and verify that each target is in scope. Resolve and pin target addresses for the scan to prevent DNS changes from escaping scope.
3. Choose an assessment profile: passive discovery, safe external checks, or staging web/API assessment.
4. Set a scan window, request rate, and optional test-account secrets. Store secrets encrypted and reveal them only to the isolated scan runner.
5. Run checks with live status, cancellation, and a complete audit trail.
6. Review and validate findings, produce a customer report, then run a scoped retest against the same environment.

## MVP capabilities

### 1. Scope and customer workspaces

- Separate tenant data and permissions for every customer.
- Record authorized domains, exact IPs/CIDRs, excluded hosts/paths, environment label, authorization reference, expiration, and contact.
- Require scope review before active checks; block expired authorizations and out-of-scope redirects or resolved IPs.
- Support analyst, approver, and read-only customer roles with MFA-ready authentication.

### 2. Passive and low-impact external discovery

- Inspect DNS records for supplied domains, including A/AAAA, CNAME, MX, NS, TXT, and DNSSEC signals where available.
- Check certificate transparency and certificate metadata for relevant hostnames; mark discovered names as candidates until approved into scope.
- Check TLS certificate validity, hostname match, chain, and supported protocol/configuration signals.
- Request approved public HTTP/HTTPS endpoints and capture status, redirect chain, response timing, and selected security headers.
- Check a narrow, configurable set of expected TCP services using rate-limited connection checks. No brute-force credential attempts.

### 3. Staging web and API assessment

- Crawl public pages and customer-provided API definitions or endpoint lists, respecting exclusions and request limits.
- Check common security configuration issues and known vulnerable component indicators where version evidence is reliable.
- Support authenticated assessment with customer-created synthetic accounts and roles. Keep credentials in a secrets store and redact them from logs and reports.
- Check role boundaries and common access-control mistakes using only test accounts and synthetic records.
- Provide safe, non-state-changing checks by default. Require explicit profile approval for any check that may create, alter, or delete test data.
- Allow customer-specific health endpoints for game lobby and WebSocket handshake checks. Do not place bets, move funds, or trigger real player actions.

### 4. Findings and reports

- Normalize each finding with title, affected asset, severity, confidence, evidence, first/last seen, reproduction notes safe for staging, and remediation guidance.
- Map findings to common categories such as TLS/DNS configuration, exposed services, web security headers, outdated components, and access-control issues.
- Deduplicate recurring findings and track status: new, confirmed, accepted risk, fixed, or retest needed.
- Generate a concise customer report plus machine-readable JSON/CSV export.
- Redact tokens, cookies, personal data, and response bodies by default. Store only the minimum evidence needed to substantiate a finding.

## Platform design

- **Web app:** customer workspaces, scope approval, scan setup, findings, reports, and audit history. Recommended MVP: Next.js with TypeScript.
- **Scan coordinator:** API for job creation, authorization checks, scheduling, cancellation, and result normalization. Recommended MVP: FastAPI with PostgreSQL and a Redis-backed job queue.
- **Isolated scan runner:** disposable worker with outbound network access restricted to the pinned approved targets; separate workers by customer/job. Worker results use a versioned JSON format and are validated before storage.
- **Windows agent:** optional later component for customer staging environments reachable only from an approved internal network. It makes outbound authenticated connections to the coordinator and has no general remote-control feature.
- **Mobile app:** later companion for scan status, alerts, approvals, and report review; full scanning is not required on mobile.
- **Storage:** PostgreSQL for tenants, scopes, jobs, and findings; encrypted object storage for limited evidence; a dedicated secrets store for test credentials.

Keep scanner checks modular so a check can be disabled, rate-limited, and independently reviewed. Keep customer-facing APIs versioned and separate from scanner worker interfaces.

### Core records

- `Tenant`: customer identity and tenant settings.
- `Authorization`: approval reference, approved-by, valid-from/to dates, and allowed assessment profiles.
- `Asset`: domain, hostname, IP, or CIDR; environment; verification status; pinned addresses; and owner.
- `ScopeRule`: included targets, exclusions, path rules, request ceilings, and scan windows.
- `ScanJob`: tenant, profile, runner version, state, timestamps, cancellation reason, and scope snapshot.
- `Finding`: check identifier, affected asset, severity, confidence, evidence reference, remediation, and lifecycle state.
- `AuditEvent`: actor, action, target record, timestamp, and outcome.

### Initial service boundaries

1. `web`: analyst and customer interface.
2. `api`: identity, tenant boundaries, authorization checks, scope management, scan scheduling, and report access.
3. `worker`: performs only the checks included in a signed scan-job scope snapshot.
4. `result-normalizer`: validates worker output, redacts sensitive values, deduplicates findings, and stores results.
5. `notifier`: sends scan completion and high-priority finding alerts without attaching sensitive evidence.

The worker must not accept arbitrary shell commands or arbitrary user-supplied code. Checks are reviewed, versioned modules with explicit network behavior and timeouts.

### Scan profiles

- **Passive:** inspect supplied target metadata and public DNS/certificate information; no application requests beyond necessary lookups.
- **Safe external:** DNS, TLS, HTTP configuration, and selected rate-limited TCP reachability checks for approved public assets.
- **Staging web/API:** safe crawl and configuration checks; optional customer-provided test accounts for role-boundary checks against synthetic data.
- **Private staging:** same approved checks from a customer-installed Windows runner, limited to the specific private targets in the job scope.

### Initial API surface

- `POST /v1/tenants/{tenant_id}/authorizations` — record approval and validity window.
- `POST /v1/tenants/{tenant_id}/assets` — add and verify candidate targets.
- `POST /v1/tenants/{tenant_id}/scans` — request a scan using an approved profile and scope snapshot.
- `POST /v1/scans/{scan_id}/cancel` — cancel a running job.
- `GET /v1/scans/{scan_id}` — read status and summary.
- `GET /v1/tenants/{tenant_id}/findings` — filter and review findings.
- `POST /v1/reports` — generate a reviewed customer report.

Every endpoint enforces tenant membership and role permissions server-side; identifiers alone never grant access.

## Security and safety controls

- Require authorization metadata and explicit target scope before active scanning.
- Default every new target to passive checks until an analyst approves active testing.
- Resolve and pin hostnames at job start; reject redirects and DNS answers outside the approved scope.
- Enforce per-target request ceilings, concurrency caps, scan windows, timeouts, and a global kill switch.
- Isolate customer jobs, encrypt data in transit and at rest, and apply least-privilege access.
- Never store customer production credentials; staging credentials are optional, encrypted, scoped, and deletable.
- Redact secrets and personal data from logs; set configurable retention and deletion schedules.
- Record who approved, launched, cancelled, viewed, exported, or deleted each scan/report.
- Require human review before marking a finding confirmed or sending a report to a customer.

## Explicit MVP exclusions

- No scanning of targets without documented authorization.
- No production testing by default, denial-of-service testing, stress testing, password spraying, brute force, persistence, exploit chaining, or data extraction.
- No payment, wallet, wager, or other state-changing transactions against real services.
- No broad internet-wide scanning or automatic promotion of discovered assets into active scope.
- No source-code access requirement. Optional code/dependency analysis can be a separate future product.

## Delivery milestones

1. **Scope and workflow design:** confirm authorization model, customer roles, scan profiles, and report format.
2. **Local prototype (implemented):** target allowlist, responsive scan UI, DNS/TLS/HTTP/health-path checks, findings view, and JSON export.
3. **Team prototype:** customer workspaces, role controls, durable audit history, and reviewed reports.
4. **Staging assessment:** isolated runner, safer web/API checks, test-account handling, rate controls, and synthetic target lab.
5. **Reports and retests:** exports, remediation tracking, retest comparison, and customer review access.
6. **Optional private-network runner:** Windows agent for approved staging assets not reachable from the public internet.
7. **Mobile companion:** alerts, approvals, scan progress, and report access.

## Acceptance criteria for the first usable release

- An analyst cannot launch an active scan without a valid authorization record and approved target list.
- The runner rejects out-of-scope DNS results, redirects, and IP addresses.
- A scan reports DNS, TLS, HTTP, and selected service reachability with timestamps and response times.
- Staging credentials and synthetic test data do not appear in logs or exports.
- Each finding has evidence, confidence, severity, and a practical remediation step.
- Customer data and scan results cannot be accessed across tenant boundaries.
- A scan can be cancelled promptly, and the cancellation is recorded.

## Decisions to confirm during implementation

- Whether the first scan runner is hosted in the team's cloud or deployed in the customer's test environment.
- Which staging formats to support first: domain/IP targets, OpenAPI document, or both.
- Initial per-target rate limits and default scan window.
- Whether customer report access is included in the first release or delivered by the analyst as an export.
