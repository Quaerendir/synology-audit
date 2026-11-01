# synology-audit

![Shell](https://img.shields.io/badge/shell-POSIX%20sh-4EAA25?style=flat-square&logo=gnu-bash)
![Platform](https://img.shields.io/badge/Synology-DSM%207%20%7C%20DSM%206.2%20%7C%20SRM-blue?style=flat-square)
![Mode](https://img.shields.io/badge/mode-read--only-success?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![Version](https://img.shields.io/badge/version-1.0.0-informational?style=flat-square)
[![CI](https://github.com/Quaerendir/synology-audit/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/Quaerendir/synology-audit/actions/workflows/shellcheck.yml)

Read-only security audit for **Synology DSM and SRM** devices. One POSIX `sh` script that runs on the NAS or router itself (or over SSH), checks the installed system against the current Synology advisories, and looks for signs of compromise and risky exposure. It changes nothing and contacts no one.

```
synology-audit 1.0.0  (advisory data: 2026-11-01)
Device : DS1522+
System : DSM 7.2.2-72806-4
Verdict: VULNERABLE

[CRIT] VERSION: DSM 7.2.2-72806-4 is below the SA-26:13 fixed build 7.2.2-72806-9: ...
[CRIT] PHP2SHELL: PHP8.2 8.2.34-0100 is below the SA-26:14 fix 8.2.35-0171 ...
```

## Why

Two things made this worth a script in autumn 2026:

- On 2026-10-29 Synology warned that attackers are encrypting data on **outdated DSM** with ransomware (reported as C3RB3R, a Cerber variant). Synology points at the December 2024 flaw from SA-24:20. Security firm 360 names two 2026 flaws that SA-26:13 fixed. Either way the defence is the same: be on a fixed build, do not expose the sign-in page, and have snapshots.
- **PHP2Shell** (SA-26:14, CVE-2026-109618/109619, CVSS 9.8) hits the PHP packages and the apps built on them (Calendar, Mail Station, Web Station sites).

Checking this by hand across a NAS and a router means reading four advisories, a package list, a firewall profile and a NAT table. The script does it in one pass.

## Advisories covered

Data snapshot **2026-11-01**, taken from the Synology advisory pages. Refresh the tables in `check_version` and `php_fixed` when Synology publishes new advisories.

| Advisory | What | Check |
|---|---|---|
| **SA-26:13** (2026-09-18, Critical) | CVE-2026-13639 and CVE-2026-13684 (CVSS 9.8, unauthenticated file read/write), plus six lower-rated flaws | DSM build against the fixed build per branch: **7.4-90075**, **7.3.2-86009-4**, **7.2.2-72806-9**, **7.2.1-69057-12** |
| **SA-24:20** (2024-11-05, Critical) | CVE-2024-10441 (CVSS 9.8, unauthenticated RCE) and two more; the flaw Synology links to the ransomware campaign | Fixed builds 7.2.2-72806-1, 7.2.1-69057-6, 7.2-64570-4, 7.1.1-42962-7, 6.2.4-25556-8. Only reported on end-of-life branches, where SA-26:13 has no fix |
| **SA-26:14** (2026-10-22, Critical) | PHP2Shell, CVE-2026-109618/109619 | PHP 7.3 (no fix), 7.4, 8.0, 8.1, 8.2, 8.3, 8.4, Calendar, Mail Station against the per-DSM fixed versions |
| SA-26:15 | Node2Shell (Brotli) | **Not checked on purpose**: it affects Synology Chat Client, a desktop app, and Chat Server is not affected |
| SRM | no SRM advisory known on the snapshot date | Version is reported; the firewall and UPnP checks still run |

## Usage

On the device, over SSH (nothing is copied to disk):

```sh
ssh admin@nas 'sh -s' < synology-audit.sh
ssh admin@nas 'sh -s -- --json' < synology-audit.sh
```

Or copy it over and run it. **Run it as root for the full picture**: without root it cannot list UPnP mappings and port forwards, read `/etc/shadow`, or read `sshd_config` on DSM. Anything it could not check is reported as `INFO`, never silently skipped.

```
--json            machine-readable output
--quiet, -q       one line: VERDICT, system, counts
--no-ioc          skip the file-system sweep (faster on large volumes)
--since DAYS      "recently modified PHP" window for web roots (default 60)
--web-root DIR    extra web root to sweep (repeatable)
```

### Verdict and exit code

| Verdict | Exit | Meaning |
|---|---|---|
| `OK` | 0 | nothing to report |
| `REVIEW` | 1 | warnings: hardening gaps, exposure, end-of-life packages |
| `VULNERABLE` | 2 | a known flaw is unpatched |
| `INDICATORS` | 3 | signs of compromise (see below) |
| `UNKNOWN` | 4 | not a Synology DSM/SRM system |

`INDICATORS` outranks `VULNERABLE`. Option errors exit 64.

## What it checks

| Area | Finding IDs | What |
|---|---|---|
| Version | `VERSION`, `VERSION-SA2420` | Build against the fixed builds above. A branch with no listed fix (7.2.0, 7.1, 7.0, 6.2) is reported **VULNERABLE**: SA-26:13 says the flaws affect builds before the fixed ones and no fixed build exists there |
| PHP2Shell | `PHP2SHELL` | PHP runtime, Calendar and Mail Station against SA-26:14. A vulnerable PHP runtime is `CRIT` only when a PHP-based package is installed (Web Station, WordPress, phpMyAdmin, MediaWiki, Joomla, KodExplorer, vtigerCRM, IDrive, Calendar, Mail Station), otherwise `WARN` |
| SSH | `SSH`, `SSH-ROOT`, `SSH-KEYS` | Whether sshd runs and on which port (`ssh_port` in `synoinfo.conf`), root login, password login, every `authorized_keys` with its fingerprints |
| SMB / NFS / FTP / Telnet | `SMB1`, `NFS`, `FTP`, `TELNET`, `LISTENING` | SMB1 allowed, NFS/rpcbind, plain-text services, every non-loopback listening port |
| Accounts | `ACCT-ADMIN`, `ACCT-GUEST` | Built-in `admin` and `guest` enabled (needs root) |
| Updates / firewall | `AUTOUPDATE`, `DSM-FIREWALL` | Auto Update task enabled, DSM firewall on |
| Packages | `PACKAGES`, `EOL-PKG`, `QUICKCONNECT` | Inventory, Python2, QuickConnect relay |
| Router exposure | `FW-ALLOWLIST`, `FW-WHITELIST`, `FW-DEFAULT`, `UPNP`, `UPNP-MAPPINGS`, `FORWARDS` | Ports allowed ahead of the geo-block, addresses allowed on every port, UPnP/NAT-PMP running, UPnP mappings and manual port forwards (root) |
| Indicators | `IOC-RANSOM`, `IOC-WEBSHELL`, `IOC-UPLOADS`, `IOC-SCHEDULE`, `IOC-PROCESS` | Ransomware-style file names, web-shell patterns, PHP in `uploads/`, download-and-run or reverse-shell commands in cron/Task Scheduler, miner processes |

### Notes on the choices

- **The ransomware sweep is a heuristic.** Synology publishes no indicator list for the campaign. The script looks for `.c3rb3r` / `.cerber*` extensions and common ransom-note names, four levels deep, on the last path component only. A clean result does not prove a clean system.
- **The geo-block does not protect the services in the router's allow-list.** On SRM the "allow" rules for SSH, SMB, VPN and HTTPS sit *before* the country DROP rules, so those ports are open to every country. `FW-ALLOWLIST` lists them. This was confirmed from a French host (blocked country) reaching an allowed router port on a real RT6600ax.
- **No network probing.** The script cannot tell whether a port is reachable from the Internet, only whether something listens and what the firewall and NAT say. Test exposure from outside with a host in a country that is not blocked.
- **Paths in reports are relative to the audited root** (identical to absolute paths on a real device).

## Tests

```sh
bash tests/run_tests.sh      # 140 checks, each against a fake DSM/SRM tree
bash tests/make_examples.sh  # regenerate examples/ from the fixtures
```

Each case builds a fixture root, runs the script as a child process under `sh` (dash in CI), and mocks `ps`, `netstat` and `iptables` so nothing on the real system is read. Test hooks (`SYNOLOGY_AUDIT_TEST_ROOT`, `SYNOLOGY_AUDIT_TEST_PATH`) are ignored when the script runs as root; a test proves it in a user namespace. The threshold table is tested at every boundary (`-3`/`-4`, `90074`/`90075`, equal and strictly newer). Mutation-tested: each fix was broken on a copy and a test failed.

CI runs `dash -n`, the tests and ShellCheck on every push.

## Limits

- Targets DSM 6.2 to 7.4 and SRM 1.3. Run end to end on a real DS1522+ (DSM 7.4.1). The SRM checks were written from the files of an RT6600ax (SRM 1.3.2: `VERSION`, firewall profile, NAT table, process list) and run against fixtures built from them, but the script has not run on a live router yet. DSM 6.2 to 7.3 are covered by the fixtures only.
- BusyBox 1.16 (SRM) is the lowest common denominator: no `sed -E`, no `cat -v`; the script avoids them.
- The sweep reads a lot of directory entries on big volumes. `--no-ioc` skips it.
- It reports; it does not fix. Fixes (turn off UPnP, raise the SMB minimum, disable `admin`) stay your decision.

## Disclaimer

Provided as is, under MIT. A clean report is not a guarantee. Read Synology's advisories at <https://www.synology.com/security> for the authoritative fixed versions.

## License

[MIT](LICENSE)
