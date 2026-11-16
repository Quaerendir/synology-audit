# Changelog

All notable changes to `synology-audit` are documented here.

## [Unreleased]

### Fixed — verdicts (review before relying on exit codes)
- A run stopped by a signal (Ctrl-C during the file sweep, `kill`, a dropped SSH session) no longer ends with `Verdict: OK` and exit 0. The signal trap removed the temp directory but did not stop the script, which then counted zero findings. The run now stops with no verdict: exit 130 (INT), 143 (TERM) or 129 (HUP).
- If the findings file is missing or empty when the report is built (temp directory removed, disk full), the result is UNKNOWN with exit 4 instead of OK.
- A cron or Task Scheduler line with `rsync -e ssh ...` (or `rsync -avhe ...`) was reported as a reverse shell, giving the verdict INDICATORS: the netcat pattern matched the "nc -e" inside it. netcat (`nc`, `ncat`, `netcat`) must now start a word.
- A file sweep that hit its time limit was reported as clean. It is now a WARN (`IOC-RANSOM` / `IOC-WEBSHELL`: "stopped at its ... limit, the rest is unchecked"), so the verdict is REVIEW instead of OK; hits found before the limit are still CRIT.
- `timeout` is used only if it accepts `timeout SECONDS CMD`; with BusyBox before 1.30 every search failed instead of running, and read as clean.
- With `ss -tln` as the fallback for a missing `netstat`, no listening port was recognised (Telnet/FTP/NFS findings were lost). All of 127.0.0.0/8 counts as loopback.
- The test hooks stay off when `id` gives no answer.

## [1.0.2] — 2026-11-01

### Changed
- The Python2 end-of-life warning now says **what depends on it**. Package Center refuses to remove Python2 while a package lists it in `install_dep_packages` (on a DS1522+ that is Download Station 4.1.2), so "remove it if nothing needs it" was not actionable. The finding reads the dependency lists of all installed packages (colon-separated, version operators like `Python2>=2.7` and CRLF line endings handled) and names the dependents, or says that nothing depends on it and it can go.

### Added
- 156 regression checks (new: dependents named, two dependents, version operator, lower-case ID, other dependency, CRLF `INFO`); the new logic is mutation-tested.

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
