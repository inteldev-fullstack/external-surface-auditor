# Changelog

## 1.1.0

- Add an installable, offline-capable mobile report viewer that imports JSON locally and does not upload or persist report data.
- Include and smoke-check the mobile app in the packaged Windows executable.
- Serve the mobile viewer and its shell-cache service worker from the local desktop application.
- Document phone installation and local report transfer.


## 1.0.0

- Replace manual target setup with approved-scope management in the local web UI.
- Add asynchronous job status, cancellation, SQLite history and report deletion.
- Add JSON/CSV/PDF report downloads and same-scope retest comparison.
- Capture TLS certificate metadata before a closing HTTP response clears its socket.
- Add response timing, improved HTTPS redirect interpretation, finding filters and technical evidence.
- Move frontend code to static assets with a restrictive content security policy.
- Add Windows launch/install scripts, a portable executable workflow and a Linux/macOS launcher.
- Add Linux/Windows regression CI and isolated test coverage.

## 0.1.0

- Initial local allowlisted DNS/TLS/HTTP HEAD prototype.
