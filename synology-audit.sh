#!/bin/sh
# synology-audit.sh - read-only security audit of a Synology DSM / SRM device.
#
# Runs ON the device (POSIX sh, BusyBox-safe) or over SSH:
#     ssh user@nas 'sh -s' < synology-audit.sh
# It reads files and process lists only. It never changes a setting, never
# writes outside its own temp directory and never contacts the network.
#
# Exit codes: 0 OK, 1 REVIEW, 2 VULNERABLE, 3 INDICATORS, 4 UNKNOWN.

VERSION="1.0.2"
ADVISORY_SNAPSHOT="2026-11-01"

# Pin PATH (same value DSM uses for cron) so a poisoned PATH cannot swap the
# tools this script runs.
PATH="/sbin:/bin:/usr/sbin:/usr/bin:/usr/syno/sbin:/usr/syno/bin:/usr/local/sbin:/usr/local/bin"
export PATH

# Test hooks. They are ignored for root, so they cannot redirect a real audit.
R=""
if [ "$(id -u 2>/dev/null)" != "0" ]; then
  if [ -n "${SYNOLOGY_AUDIT_TEST_ROOT:-}" ]; then R="$SYNOLOGY_AUDIT_TEST_ROOT"; fi
  if [ -n "${SYNOLOGY_AUDIT_TEST_PATH:-}" ]; then PATH="$SYNOLOGY_AUDIT_TEST_PATH:$PATH"; fi
fi

usage() {
  cat <<'EOF'
Usage: synology-audit.sh [options]

  --json            machine-readable output
  --quiet, -q       one line: VERDICT, system, counts
  --no-ioc          skip the file-system sweep (ransomware / web-shell search)
  --since DAYS      "recently modified PHP" window for web roots (default 60)
  --web-root DIR    extra web root to sweep (repeatable)
  --version         print the version
  -h, --help        this text

Exit codes: 0 OK, 1 REVIEW, 2 VULNERABLE, 3 INDICATORS, 4 UNKNOWN.
Run as root for the full picture (UPnP mappings, shadow state, port forwards).
EOF
}

JSON=0
QUIET=0
NO_IOC=0
SINCE_DAYS=60
EXTRA_ROOTS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON=1 ;;
    --quiet|-q) QUIET=1 ;;
    --no-ioc) NO_IOC=1 ;;
    --since)
      if [ $# -lt 2 ]; then echo "--since needs a number of days" >&2; exit 64; fi
      shift; SINCE_DAYS="$1" ;;
    --web-root)
      if [ $# -lt 2 ]; then echo "--web-root needs a directory" >&2; exit 64; fi
      shift
      EXTRA_ROOTS="$EXTRA_ROOTS
$1" ;;
    --version) echo "synology-audit $VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 64 ;;
  esac
  shift
done
case "$SINCE_DAYS" in
  ''|*[!0-9]*) echo "--since must be a whole number of days" >&2; exit 64 ;;
esac

WORK=$(mktemp -d 2>/dev/null) || {
  WORK="/tmp/synology-audit.$$"
  (umask 077 && mkdir "$WORK") || { echo "cannot create a temp directory" >&2; exit 70; }
}
trap 'rm -rf "$WORK"' EXIT INT TERM
FIND="$WORK/findings"
: > "$FIND"

# add SEVERITY ID MESSAGE   (SEVERITY: CRIT WARN INFO OK; IDs starting IOC- are indicators)
add() { printf '%s|%s|%s\n' "$1" "$2" "$3" >> "$FIND"; }

# ver_ge A B: succeed when version A >= B. Fields split on . and -.
ver_ge() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    na = split(a, x, /[.-]/); nb = split(b, y, /[.-]/)
    n = (na > nb) ? na : nb
    for (i = 1; i <= n; i++) {
      xi = x[i] + 0; yi = y[i] + 0
      if (xi > yi) exit 0
      if (xi < yi) exit 1
    }
    exit 0
  }'
}

# build_ge BUILD FIX NEED_BUILD NEED_FIX: succeed when BUILD-FIX >= NEED_BUILD-NEED_FIX
build_ge() {
  if [ "$1" -gt "$3" ]; then return 0; fi
  if [ "$1" -lt "$3" ]; then return 1; fi
  [ "$2" -ge "$4" ]
}

num_or_zero() {
  case "$1" in
    ''|*[!0-9]*) echo 0 ;;
    *) echo "$1" ;;
  esac
}

# kv KEY: value of KEY= in the VERSION file, quotes stripped.
kv() { grep "^$1=" "$VERFILE" 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d '"'; }

# conf_kv FILE KEY
conf_kv() { grep "^$2=" "$1" 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d '"'; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# unroot: print paths relative to the audited root (only differs in tests)
unroot() {
  if [ -n "$R" ]; then sed "s|$R||g"; else cat; fi
}

# ---------------------------------------------------------------- identify
OS="unknown"
PV=""
BUILD=0
FIX=0
UNIQ=""
MODEL=""
VERFILE="$R/etc.defaults/VERSION"
[ -r "$VERFILE" ] || VERFILE="$R/etc/VERSION"
INFOCONF="$R/etc.defaults/synoinfo.conf"
[ -r "$INFOCONF" ] || INFOCONF="$R/etc/synoinfo.conf"

identify() {
  [ -r "$VERFILE" ] || return 1
  PV=$(kv productversion)
  BUILD=$(num_or_zero "$(kv buildnumber)")
  FIX=$(num_or_zero "$(kv smallfixnumber)")
  OSN=$(kv os_name)
  UNIQ=$(conf_kv "$INFOCONF" unique)
  MODEL=$(conf_kv "$INFOCONF" upnpmodelname)
  [ -n "$MODEL" ] || MODEL="$UNIQ"
  case "$OSN" in
    DSM|SRM|BSM) OS="$OSN" ;;
    *)
      case "$UNIQ" in
        *_rt[0-9]*|*_mr[0-9]*|*_wrx*) OS="SRM" ;;
        *)
          case "$PV" in
            6.*|7.*) OS="DSM" ;;
            *) OS="unknown" ;;
          esac ;;
      esac ;;
  esac
  [ "$OS" != "unknown" ]
}

# --------------------------------------------------------------- snapshots
PS_OUT=$( (ps -eo user,pid,args 2>/dev/null || ps w 2>/dev/null || ps 2>/dev/null) )
NS_OUT=$( (netstat -tln 2>/dev/null || ss -tln 2>/dev/null) )
LISTEN_EXT=$(printf '%s\n' "$NS_OUT" | awk '$1 ~ /^tcp/ {
  a = $4; n = split(a, p, ":"); port = p[n]
  addr = substr(a, 1, length(a) - length(port) - 1)
  if (addr == "127.0.0.1" || addr == "::1" || addr == "[::1]") next
  print port }' | sort -un | tr '\n' ' ')
LISTEN_EXT=${LISTEN_EXT% }

listening() { # listening PORT
  for lp in $LISTEN_EXT; do [ "$lp" = "$1" ] && return 0; done
  return 1
}

# ---------------------------------------------------------- version checks
SYSTEM_STR=""
check_version() {
  SYSTEM_STR="$OS $PV-$BUILD"
  [ "$FIX" -gt 0 ] && SYSTEM_STR="$SYSTEM_STR-$FIX"
  case "$OS" in
    DSM)
      NB=""; NF=0
      case "$PV" in
        7.4*) NB=90075; NF=0; FIXED="7.4-90075" ;;
        7.3*) NB=86009; NF=4; FIXED="7.3.2-86009-4" ;;
        7.2.2*) NB=72806; NF=9; FIXED="7.2.2-72806-9" ;;
        7.2.1*) NB=69057; NF=12; FIXED="7.2.1-69057-12" ;;
      esac
      if [ -n "$NB" ]; then
        if build_ge "$BUILD" "$FIX" "$NB" "$NF"; then
          add OK VERSION "$SYSTEM_STR is at or above the SA-26:13 fixed build $FIXED (CVE-2026-13639, CVE-2026-13684)"
        else
          add CRIT VERSION "$SYSTEM_STR is below the SA-26:13 fixed build $FIXED: CVE-2026-13639 and CVE-2026-13684 (CVSS 9.8, unauthenticated file read/write); update DSM now"
        fi
      else
        add CRIT VERSION "$SYSTEM_STR is on a branch with no SA-26:13 fix (Synology lists fixes only for 7.4, 7.3, 7.2.2 and 7.2.1); upgrade to a supported DSM"
        case "$PV" in
          7.2*) SN=64570; SF=4; SFIXED="7.2-64570-4" ;;
          7.1*) SN=42962; SF=7; SFIXED="7.1.1-42962-7" ;;
          6.2*) SN=25556; SF=8; SFIXED="6.2.4-25556-8" ;;
          *) SN=""; SFIXED="" ;;
        esac
        if [ -n "$SN" ]; then
          if ! build_ge "$BUILD" "$FIX" "$SN" "$SF"; then
            add CRIT VERSION-SA2420 "$SYSTEM_STR is also below the SA-24:20 fixed build $SFIXED (CVE-2024-10441, unauthenticated RCE). Synology says the C3RB3R ransomware campaign exploits a flaw patched in December 2024"
          fi
        fi
      fi ;;
    SRM)
      add INFO VERSION "$SYSTEM_STR: no SRM advisory is known to this script (snapshot $ADVISORY_SNAPSHOT). Check https://www.synology.com/security and keep SRM and its packages on automatic update" ;;
    BSM)
      add INFO VERSION "$SYSTEM_STR: BeeStation OS is only partly covered (SA-24:20 fixed in 1.1-65374). Check https://www.synology.com/security" ;;
  esac
}

# ------------------------------------------------------- package inventory
PKGLIST="$WORK/pkgs"
DEPLIST="$WORK/deps"
: > "$PKGLIST"
: > "$DEPLIST"
collect_packages() {
  for info in "$R"/var/packages/*/INFO; do
    [ -r "$info" ] || continue
    pid=$(basename "$(dirname "$info")")
    pver=$(grep '^version=' "$info" 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d '"')
    printf '%s %s\n' "$pid" "$pver" >> "$PKGLIST"
    # install_dep_packages="Python2>=2.7:WebStation": colon-separated, optional version operator
    pdeps=$(grep '^install_dep_packages=' "$info" 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d '"\r')
    if [ -n "$pdeps" ]; then
      printf '%s\n' "$pdeps" | tr ':' '\n' | sed 's/[<>=].*//' | while IFS= read -r dep; do
        if [ -n "$dep" ]; then printf '%s %s\n' "$pid" "$dep" >> "$DEPLIST"; fi
      done
    fi
  done
}

# dependents ID: installed packages that declare ID as a dependency, comma-separated
dependents() {
  awk -v d="$1" 'tolower($2) == tolower(d) { printf "%s%s", sep, $1; sep = ", " }' "$DEPLIST"
}

pkg_version() { awk -v id="$1" 'tolower($1) == tolower(id) { print $2; exit }' "$PKGLIST"; }
pkg_present() { [ -n "$(awk -v id="$1" 'tolower($1) == tolower(id) { print "y"; exit }' "$PKGLIST")" ]; }

dsm_family() {
  case "$PV" in
    7.0*|7.1*) echo 70 ;;
    7.*) echo 72 ;;
    6.*) echo 62 ;;
    *) echo 72 ;;
  esac
}

# php_fixed ID FAMILY: prints the SA-26:14 fixed version, EOL, or NA
php_fixed() {
  case "$1" in
    PHP7.3) echo EOL ;;
    PHP7.4)
      case "$2" in 72) echo 7.4.33-0131 ;; 70) echo 7.4.33-0122 ;; *) echo 7.4.33-0010 ;; esac ;;
    PHP8.0)
      case "$2" in 72) echo 8.0.30-0122 ;; 70) echo 8.0.30-0104 ;; *) echo NA ;; esac ;;
    PHP8.1) echo 8.1.34-0120 ;;
    PHP8.2) echo 8.2.35-0171 ;;
    PHP8.3) echo 8.3.36-0051 ;;
    PHP8.4) echo 8.4.27-0051 ;;
    Calendar)
      case "$2" in 72) echo 3.0.4-21435 ;; 70) echo 2.4.8-10948 ;; *) echo 2.4.8-0948 ;; esac ;;
    MailStation)
      case "$2" in 72) echo 30000002.3.19-20333 ;; 70) echo 30000002.3.19-10333 ;; *) echo 30000002.3.19-0333 ;; esac ;;
    *) echo NA ;;
  esac
}

check_packages() {
  if [ -s "$PKGLIST" ]; then
    npk=$(wc -l < "$PKGLIST" | tr -d ' ')
    add INFO PACKAGES "$npk packages installed: $(awk '{ printf "%s%s", sep, $1; sep = ", " }' "$PKGLIST")"
  else
    add INFO PACKAGES "no packages found under /var/packages"
  fi

  [ "$OS" = "DSM" ] || return 0

  fam=$(dsm_family)
  deps=""
  for d in WebStation WordPress phpMyAdmin MediaWiki Joomla KodExplorer vtigerCRM IDrive Calendar MailStation; do
    if pkg_present "$d"; then deps="$deps $d"; fi
  done
  deps=${deps# }

  found_php=0
  # every PHP runtime package, including ones SA-26:14 does not list
  for pid in $(awk '$1 ~ /^[Pp][Hh][Pp][0-9]/ { print $1 }' "$PKGLIST"); do
    found_php=1
    ver=$(pkg_version "$pid")
    fixed=$(php_fixed "$pid" "$fam")
    case "$fixed" in
      EOL)
        if [ -n "$deps" ]; then
          add CRIT PHP2SHELL "$pid $ver is end of life and has no PHP2Shell fix (CVE-2026-109618/109619) while PHP-based packages are installed ($deps); remove it and move the sites to PHP 8.4"
        else
          add WARN PHP2SHELL "$pid $ver is end of life and has no PHP2Shell fix; no PHP-based package is installed, but remove it"
        fi ;;
      NA)
        add WARN PHP2SHELL "$pid $ver is not in the SA-26:14 table; if it is end of life, remove it"  ;;
      *)
        if ver_ge "$ver" "$fixed"; then
          add OK PHP2SHELL "$pid $ver is at or above the SA-26:14 fix $fixed"
        elif [ -n "$deps" ]; then
          add CRIT PHP2SHELL "$pid $ver is below the SA-26:14 fix $fixed (CVE-2026-109618/109619, CVSS 9.8, remote code execution) and PHP-based packages are installed ($deps); update it in Package Center"
        else
          add WARN PHP2SHELL "$pid $ver is below the SA-26:14 fix $fixed but no PHP-based package is installed; update it anyway"
        fi ;;
    esac
  done

  for pid in Calendar MailStation; do
    pkg_present "$pid" || continue
    found_php=1
    ver=$(pkg_version "$pid")
    fixed=$(php_fixed "$pid" "$fam")
    if ver_ge "$ver" "$fixed"; then
      add OK PHP2SHELL "$pid $ver is at or above the SA-26:14 fix $fixed"
    else
      add CRIT PHP2SHELL "$pid $ver is below the SA-26:14 fix $fixed (remote code execution); update it in Package Center (Mail Station needs a manual update)"
    fi
  done

  if [ "$found_php" -eq 0 ]; then
    add OK PHP2SHELL "no PHP runtime, Calendar or Mail Station package installed: SA-26:14 (PHP2Shell) does not apply"
  fi

  if pkg_present Python2; then
    py2users=$(dependents Python2)
    if [ -n "$py2users" ]; then
      add WARN EOL-PKG "Python2 $(pkg_version Python2) is end of life and Package Center will not remove it while $py2users depend(s) on it; uninstall that first, or keep it updated and off the Internet"
    else
      add WARN EOL-PKG "Python2 $(pkg_version Python2) is end of life and no installed package depends on it; remove it"
    fi
  fi
}

# ------------------------------------------------------------------- ssh
SSHCONF="$R/etc/ssh/sshd_config"
check_ssh() {
  if printf '%s\n' "$PS_OUT" | grep -Eq 'sshd.*\[listener\]|sshd -D|/usr/s?bin/sshd'; then
    # DSM/SRM keep the configured port in synoinfo.conf, not in sshd_config
    port=$(conf_kv "$R/etc/synoinfo.conf" ssh_port)
    [ -n "$port" ] || port=$(awk '$1 == "Port" { print $2; exit }' "$SSHCONF" 2>/dev/null)
    [ -n "$port" ] || port=22
    add WARN SSH "SSH is enabled (port $port). Turn it off when you are not using it; it is reachable from the Internet unless the firewall or NAT blocks it"
    if [ -r "$SSHCONF" ]; then
      prl=$(awk 'tolower($1) == "permitrootlogin" { print $2; exit }' "$SSHCONF" 2>/dev/null)
      if [ "$prl" = "yes" ]; then
        add WARN SSH-ROOT "sshd has PermitRootLogin yes: root can log in with a password"
      fi
      pa=$(awk 'tolower($1) == "passwordauthentication" { print $2; exit }' "$SSHCONF" 2>/dev/null)
      if [ "$pa" != "no" ]; then
        add INFO SSH-PASSWORD "sshd accepts passwords; keys only (PasswordAuthentication no) is safer"
      fi
    else
      add INFO SSH-CONFIG "sshd_config is not readable (run as root to check PermitRootLogin and PasswordAuthentication)"
    fi
  else
    add OK SSH "SSH is not running"
  fi

  for ak in "$R"/etc/ssh/keys/*/authorized_keys "$R"/var/services/homes/*/.ssh/authorized_keys "$R"/root/.ssh/authorized_keys; do
    [ -r "$ak" ] || continue
    case "$ak" in
      */etc/ssh/keys/*) owner=$(basename "$(dirname "$ak")") ;;
      */root/.ssh/*) owner=root ;;
      *) owner=$(basename "$(dirname "$(dirname "$ak")")") ;;
    esac
    # count key lines only (a file saved with CRLF endings has blank "\r" lines)
    nkeys=$(grep -Ec '(ssh-(rsa|ed25519|dss)|ecdsa-sha2-|sk-)' "$ak" 2>/dev/null)
    fps=""
    if has_cmd ssh-keygen; then
      fps=$(ssh-keygen -lf "$ak" 2>/dev/null | tr -d '\r' | awk '{ fp = $2; $1 = ""; $2 = ""; sub(/ \([A-Za-z0-9-]+\)$/, ""); sub(/^ +/, ""); printf "%s%s %s", sep, fp, $0; sep = "; " }')
    fi
    add INFO SSH-KEYS "authorized_keys for $owner: ${nkeys:-0} key(s)${fps:+ ($fps)}"
  done
}

# ------------------------------------------------------------- smb / nfs
check_shares() {
  smbconf="$R/etc/samba/smb.conf"
  if [ -r "$smbconf" ]; then
    minp=$(grep -i '^[[:space:]]*min protocol' "$smbconf" 2>/dev/null | head -n 1 | cut -d= -f2 | tr -d ' \t' | tr 'a-z' 'A-Z')
    case "$minp" in
      NT1|CORE|COREPLUS|LANMAN1|LANMAN2)
        add WARN SMB1 "SMB1 is allowed (min protocol=$minp): raise the minimum to SMB2 or higher (Control Panel > File Services > SMB > Advanced) after checking old scanners and printers" ;;
      '') ;;
      *) add OK SMB1 "SMB minimum protocol is $minp" ;;
    esac
  fi
  if listening 2049 || listening 111; then
    add INFO NFS "NFS/rpcbind is listening (2049/111); disable NFS if no client uses it"
  fi
  for tp in 21 23; do
    if listening "$tp"; then
      case "$tp" in
        21) add WARN FTP "FTP is listening on 21: plain-text logins; use SFTP or disable it" ;;
        23) add WARN TELNET "Telnet is listening on 23: plain-text logins; disable it" ;;
      esac
    fi
  done
  if [ -n "$LISTEN_EXT" ]; then
    add INFO LISTENING "ports listening on non-loopback addresses: $LISTEN_EXT"
  fi
}

# --------------------------------------------------------------- accounts
check_accounts() {
  grp="$R/etc/group"
  if [ -r "$grp" ]; then
    adm=$(awk -F: '$1 == "administrators" { print $4 }' "$grp")
    [ -n "$adm" ] && add INFO ACCOUNTS "administrators group: $adm"
  fi
  shadow="$R/etc/shadow"
  if [ -r "$shadow" ]; then
    # DSM keeps the hash of a disabled account and marks it expired instead
    # (shadow field 8 = day number since 1970, observed value 1).
    today=$(( $(date +%s 2>/dev/null || echo 0) / 86400 ))
    for acct in admin guest; do
      rec=$(awk -F: -v u="$acct" '$1 == u { print $2 ":" $8 }' "$shadow")
      [ -n "$rec" ] || continue
      st=${rec%%:*}
      ex=${rec#*:}
      enabled=0
      case "$st" in '$'*) enabled=1 ;; esac
      case "$ex" in
        ''|*[!0-9]*) ;;
        *) if [ "$ex" -le "$today" ]; then enabled=0; fi ;;
      esac
      if [ "$enabled" -eq 1 ]; then
        case "$acct" in
          admin) add WARN ACCT-ADMIN "the built-in admin account is enabled; use a named administrator and disable admin" ;;
          guest) add WARN ACCT-GUEST "the guest account is enabled; disable it" ;;
        esac
      fi
    done
  elif [ -r "$grp" ]; then
    add INFO ACCOUNTS "run as root to check whether the admin and guest accounts are disabled"
  fi
}

# --------------------------------------------------- updates / schedule
check_updates() {
  [ "$OS" = "DSM" ] || return 0
  su_ok=0
  for tk in "$R"/usr/syno/etc/synoschedule.d/*/*.task; do
    [ -r "$tk" ] || continue
    if grep -q 'DSMAutoUpdate' "$tk" 2>/dev/null && grep -q '^state=enabled' "$tk" 2>/dev/null; then su_ok=1; fi
  done
  if [ "$su_ok" -eq 1 ]; then
    add OK AUTOUPDATE "the DSM Auto Update task is enabled"
  else
    add WARN AUTOUPDATE "no enabled DSM Auto Update task found (Control Panel > Update & Restore); automatic updates are Synology's main advice against ransomware"
  fi
  fw="$R/usr/syno/etc/firewall.d/firewall_settings.json"
  if [ -r "$fw" ]; then
    if grep -q '"status" *: *true' "$fw"; then
      add OK DSM-FIREWALL "the DSM firewall is enabled"
    else
      add WARN DSM-FIREWALL "the DSM firewall is disabled"
    fi
  fi
}

# Suspicious commands in cron or scheduled tasks.
SUSPICIOUS_CMD='(curl|wget)[^|]*\|[[:space:]]*(ba|da|a)?sh|base64[[:space:]]+(-d|--decode)|/dev/tcp/|nc[[:space:]]+(-[a-z]*e|-c)|mkfifo|/tmp/[.a-zA-Z0-9_-]+\.(sh|py|pl)|xmrig|minerd|kinsing'
check_schedule() {
  hits=""
  for f in "$R"/etc/crontab "$R"/var/spool/cron/crontabs/* "$R"/usr/syno/etc/synoschedule.d/*/*.task; do
    [ -r "$f" ] && [ -f "$f" ] || continue
    if grep -Eiq "$SUSPICIOUS_CMD" "$f" 2>/dev/null; then hits="$hits $f"; fi
  done
  if [ -n "$hits" ]; then
    add CRIT IOC-SCHEDULE "scheduled task or cron entry runs a suspicious command (download-and-run, base64, reverse shell or miner):$(printf '%s' "$hits" | unroot)"
  else
    add OK SCHEDULE "no suspicious command in cron or Task Scheduler"
  fi
}

check_processes() {
  bad=$(printf '%s\n' "$PS_OUT" | grep -Ei 'xmrig|minerd|cpuminer|ccminer|kinsing|kdevtmpfsi|/dev/shm/|/var/tmp/[^ ]*\.(sh|bin)' | grep -v 'grep' | head -n 5)
  if [ -n "$bad" ]; then
    add CRIT IOC-PROCESS "suspicious process(es): $(printf '%s' "$bad" | tr '\n' ';' | cut -c1-300)"
  else
    add OK PROCESSES "no miner or temp-directory process found"
  fi
}

# ------------------------------------------------------------ ioc sweep
# Applied to the last path component only. Heuristic: Synology publishes no IOC list.
RANSOM_RE='/[^/]*(\.c3rb3r|\.cerber[23]?|decrypt[^/]*my[^/]*files|r_e_a_d[^/]*t_h_i_s|how[^/]*to[^/]*recover[^/]*files|restore[^/]*your[^/]*files)[^/]*$'
WEBSHELL_RE='eval\(base64_decode|eval\(gzinflate|assert\(\$_(POST|GET|REQUEST)|system\(\$_(POST|GET|REQUEST)|passthru\(\$_|shell_exec\(\$_|FilesMan|c99shell|r57shell'

web_roots() {
  for d in "$R"/volume*/web "$R"/volume*/web_packages "$R"/var/services/web*; do
    [ -d "$d" ] && printf '%s\n' "$d"
  done
  printf '%s\n' "$EXTRA_ROOTS" | while IFS= read -r d; do
    [ -n "$d" ] && [ -d "$d" ] && printf '%s\n' "$d"
  done
}

run_timeout() { # run_timeout SECONDS CMD...
  secs="$1"; shift
  if has_cmd timeout; then timeout "$secs" "$@"; else "$@"; fi
}

check_ioc() {
  hits=""
  for vol in "$R"/volume*; do
    [ -d "$vol" ] || continue
    found=$(run_timeout 90 find "$vol" -maxdepth 4 -type f 2>/dev/null | grep -Ei "$RANSOM_RE" | head -n 10)
    [ -n "$found" ] && hits="$hits
$found"
  done
  if [ -n "$hits" ]; then
    add CRIT IOC-RANSOM "file names typical of the Cerber/C3RB3R ransomware (heuristic, Synology publishes no IOC list):$(printf '%s' "$hits" | unroot | tr '\n' ' ' | cut -c1-400)"
  else
    add OK IOC-RANSOM "no ransomware-style file or ransom-note name on the volumes (searched 4 levels deep)"
  fi

  roots=$(web_roots)
  if [ -z "$roots" ]; then
    add OK IOC-WEB "no web root found (no Web Station content)"
    return 0
  fi
  shells=""
  recent=0
  upl=""
  for wr in $roots; do
    s=$(run_timeout 60 grep -rlE "$WEBSHELL_RE" "$wr" 2>/dev/null | head -n 10)
    [ -n "$s" ] && shells="$shells
$s"
    n=$(run_timeout 60 find "$wr" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \) -mtime "-$SINCE_DAYS" 2>/dev/null | wc -l | tr -d ' ')
    recent=$((recent + ${n:-0}))
    u=$(run_timeout 60 find "$wr" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \) 2>/dev/null |
      awk -v root="$wr" 'index($0, root) == 1 { rel = substr($0, length(root) + 1) } tolower(rel) ~ /\/(uploads?|cache|tmp)\// { print }' | head -n 5)
    [ -n "$u" ] && upl="$upl
$u"
  done
  if [ -n "$shells" ]; then
    add CRIT IOC-WEBSHELL "web-shell patterns in web roots:$(printf '%s' "$shells" | unroot | tr '\n' ' ' | cut -c1-400)"
  else
    add OK IOC-WEBSHELL "no web-shell pattern in the web roots"
  fi
  if [ -n "$upl" ]; then
    add WARN IOC-UPLOADS "PHP files inside uploads/cache/tmp directories:$(printf '%s' "$upl" | unroot | tr '\n' ' ' | cut -c1-400)"
  fi
  if [ "$recent" -gt 0 ]; then
    add INFO WEB-RECENT "$recent PHP file(s) changed in the web roots in the last $SINCE_DAYS days"
  fi
}

# ------------------------------------------------- router: upnp / firewall
check_exposure() {
  # SRM firewall profile as rendered by the router
  fwf="$R/tmp/firewall_iptables_rules_v4"
  if [ -r "$fwf" ]; then
    allowed=$(awk '
      /^-A INPUT_FIREWALL/ && /geoip/ && /-j DROP/ { geo = 1 }
      /^-A INPUT_FIREWALL/ && /-j RETURN/ && !/ -s / && !geo {
        if (match($0, /--dports? [0-9,]+/)) {
          s = substr($0, RSTART, RLENGTH); sub(/--dports? /, "", s); print s } }' "$fwf" |
      tr ',' '\n' | sort -un | tr '\n' ' ')
    allowed=${allowed% }
    if [ -n "$allowed" ]; then
      add WARN FW-ALLOWLIST "router ports allowed from any country, ahead of the geo-block: $allowed. The geo-block does not protect these"
    fi
    wl=$(grep '^-A INPUT_FIREWALL' "$fwf" | grep -- '-j RETURN' | grep -- ' -s ' | sed -n 's/.* -s \([0-9./]*\).*/\1/p' | sort -u | tr '\n' ' ')
    wl=${wl% }
    if [ -n "$wl" ]; then
      add INFO FW-WHITELIST "source address(es) allowed on every router port: $wl"
    fi
    if ! grep -q '^-A INPUT_FIREWALL -j DROP' "$fwf"; then
      add WARN FW-DEFAULT "no final DROP in the router INPUT firewall chain"
    fi
  fi

  if printf '%s\n' "$PS_OUT" | grep -q 'miniupnpd'; then
    add WARN UPNP "UPnP/NAT-PMP is running: devices on the LAN can open ports to the Internet without asking"
  fi

  # NAT mappings need root
  if has_cmd iptables; then
    nat=$(iptables -t nat -S 2>/dev/null)
  else
    nat=""
  fi
  if [ -n "$nat" ]; then
    upnp_map=$(printf '%s\n' "$nat" | grep -E '^-A NUPNPD .*DNAT' | sed -n 's/.*--dport \([0-9]*\).*--to-destination \(.*\)/\1->\2/p' | tr '\n' ' ')
    static_map=$(printf '%s\n' "$nat" | grep -E '^-A PORT_FORWARD_RULE .*DNAT' | sed -n 's/.*-p \([a-z]*\).*--dport \([0-9]*\).*--to-destination \(.*\)/\1 \2->\3/p' | tr '\n' ';')
    [ -n "$upnp_map" ] && add WARN UPNP-MAPPINGS "UPnP port mappings to the LAN: ${upnp_map% }"
    [ -n "$static_map" ] && add INFO FORWARDS "manual port forwards: ${static_map%;}"
  elif [ "$OS" = "SRM" ]; then
    add INFO NAT "run as root to list UPnP mappings and port forwards (iptables -t nat)"
  fi
}

check_quickconnect() {
  if pkg_present QuickConnect || printf '%s\n' "$PS_OUT" | grep -q 'synorelayd'; then
    add INFO QUICKCONNECT "QuickConnect/relay is active: the sign-in page is reachable through Synology's relay; keep 2FA on every account"
  fi
}

# -------------------------------------------------------------- run it all
if ! identify; then
  if [ "$QUIET" -eq 1 ]; then
    echo "UNKNOWN not a Synology DSM/SRM system"
  elif [ "$JSON" -eq 1 ]; then
    printf '{"tool":"synology-audit","version":"%s","verdict":"UNKNOWN","exit":4,"findings":[]}\n' "$VERSION"
  else
    echo "synology-audit $VERSION: cannot find /etc.defaults/VERSION - this does not look like Synology DSM or SRM." >&2
  fi
  exit 4
fi

collect_packages
check_version
check_packages
check_ssh
check_shares
check_accounts
check_updates
check_schedule
check_processes
check_quickconnect
check_exposure
if [ "$NO_IOC" -eq 0 ]; then check_ioc; fi

# ------------------------------------------------------------------ report
n_crit=$(grep -c '^CRIT|' "$FIND")
n_warn=$(grep -c '^WARN|' "$FIND")
n_info=$(grep -c '^INFO|' "$FIND")
n_ok=$(grep -c '^OK|' "$FIND")
n_ioc=$(grep -c '^CRIT|IOC-' "$FIND")

if [ "$n_ioc" -gt 0 ]; then
  VERDICT=INDICATORS; EXITC=3
elif [ "$n_crit" -gt 0 ]; then
  VERDICT=VULNERABLE; EXITC=2
elif [ "$n_warn" -gt 0 ]; then
  VERDICT=REVIEW; EXITC=1
else
  VERDICT=OK; EXITC=0
fi

json_esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\t' ' '; }

if [ "$QUIET" -eq 1 ]; then
  echo "$VERDICT $SYSTEM_STR $MODEL: $n_crit critical, $n_warn warnings"
  exit "$EXITC"
fi

if [ "$JSON" -eq 1 ]; then
  printf '{"tool":"synology-audit","version":"%s","advisory_snapshot":"%s",' "$VERSION" "$ADVISORY_SNAPSHOT"
  printf '"os":"%s","model":"%s","product_version":"%s","build":%s,"smallfix":%s,' \
    "$OS" "$(json_esc "$MODEL")" "$(json_esc "$PV")" "$BUILD" "$FIX"
  printf '"verdict":"%s","exit":%s,"counts":{"critical":%s,"warning":%s,"info":%s,"ok":%s},"findings":[' \
    "$VERDICT" "$EXITC" "$n_crit" "$n_warn" "$n_info" "$n_ok"
  first=1
  while IFS= read -r line; do
    sev=${line%%|*}; rest=${line#*|}; fid=${rest%%|*}; msg=${rest#*|}
    [ "$first" -eq 1 ] || printf ','
    first=0
    printf '{"severity":"%s","id":"%s","message":"%s"}' "$sev" "$fid" "$(json_esc "$msg")"
  done < "$FIND"
  printf ']}\n'
  exit "$EXITC"
fi

echo "synology-audit $VERSION  (advisory data: $ADVISORY_SNAPSHOT)"
echo "Device : $MODEL"
echo "System : $SYSTEM_STR"
echo "Verdict: $VERDICT"
echo
for sev in CRIT WARN INFO OK; do
  case "$sev" in
    CRIT) label="CRIT" ;;
    WARN) label="WARN" ;;
    INFO) label="INFO" ;;
    OK) label=" OK " ;;
  esac
  while IFS= read -r line; do
    s=${line%%|*}
    [ "$s" = "$sev" ] || continue
    rest=${line#*|}; fid=${rest%%|*}; msg=${rest#*|}
    printf '[%s] %s: %s\n' "$label" "$fid" "$msg"
  done < "$FIND"
done
echo
echo "$n_crit critical, $n_warn warning(s), $n_info info, $n_ok ok"
exit "$EXITC"
