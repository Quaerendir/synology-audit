# Changelog

All notable changes to `synology-audit` are documented here.

## [1.0.1] — 2026-11-01

### Fixed
- **Disabled accounts were reported as enabled.** DSM keeps the password hash of a disabled account and marks it expired instead (`/etc/shadow` field 8, observed value `1`). The `admin`/`guest` check treated any `$` hash as enabled, so a disabled `guest` raised `ACCT-GUEST`. An account whose expiry day is today or earlier is now disabled. Found on a real DS1522+ run as root.
- A key file saved with CRLF line endings (for example one uploaded from Windows with `type file | ssh`) made the `SSH-KEYS` line garbled and counted the blank `\r` line as a key. Carriage returns are stripped and only real key lines are counted.

### Changed
- 148 regression checks (new: expired and future-expiry accounts, CRLF key files); the new logic is mutation-tested.

## [1.0.0] — 2026-11-01

### Added
- First release. Read-only POSIX `sh` audit for Synology DSM 6.2 to 7.4 and SRM 1.3, runnable on the device or over SSH.
- Version check against SA-26:13 (fixed builds 7.4-90075, 7.3.2-86009-4, 7.2.2-72806-9, 7.2.1-69057-12) and SA-24:20 for end-of-life branches. Branches with no listed fix are reported VULNERABLE.
- PHP2Shell (SA-26:14) check for the PHP 7.3 to 8.4 packages, Calendar and Mail Station, with the per-DSM fixed versions; a vulnerable PHP runtime is critical only when a PHP-based package is installed.
- SSH, SMB1, NFS, FTP, Telnet, account, auto-update, DSM firewall and QuickConnect checks.
- Router checks: ports allowed ahead of the geo-block, allowed source addresses, UPnP/NAT-PMP, UPnP mappings and manual port forwards (root).
- Indicator sweep: ransomware-style names, web-shell patterns, PHP in `uploads/`, suspicious cron/Task Scheduler commands, miner processes.
- `--json`, `--quiet`, `--no-ioc`, `--since`, `--web-root`. Exit codes 0 OK, 1 REVIEW, 2 VULNERABLE, 3 INDICATORS, 4 UNKNOWN.
- 140 regression checks, ShellCheck and `dash -n` in CI.
