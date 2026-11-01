#!/usr/bin/env bash
# Regenerate examples/*.txt and examples/*.json from fake fixture trees.
# Nothing here comes from a real device.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/synology-audit.sh"
MOCK_BIN="$ROOT/tests/mock_bin"
OUTDIR="$ROOT/examples"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUTDIR"
chmod +x "$MOCK_BIN"/*

base() { # base NAME PV BUILD FIX
  D="$TMP/$1"
  mkdir -p "$D/etc.defaults" "$D/etc/samba" "$D/var/packages" "$D/tmp" \
    "$D/usr/syno/etc/synoschedule.d/root" "$D/usr/syno/etc/firewall.d"
  printf 'productversion="%s"\nbuildnumber="%s"\nsmallfixnumber="%s"\nos_name="DSM"\n' "$2" "$3" "$4" > "$D/etc.defaults/VERSION"
  printf 'unique="synology_r1000_1522+"\nupnpmodelname="DS1522+"\n' > "$D/etc.defaults/synoinfo.conf"
  printf 'type=daily\nname=DSM Auto Update\nstate=enabled\napp=SYNO.SDS.TaskScheduler.DSMAutoUpdate\n' > "$D/usr/syno/etc/synoschedule.d/root/1.task"
  printf '{ "status" : true }\n' > "$D/usr/syno/etc/firewall.d/firewall_settings.json"
  printf '[global]\n\tmin protocol=SMB2\n' > "$D/etc/samba/smb.conf"
  printf 'administrators:x:101:alice\n' > "$D/etc/group"
}
pkg() { mkdir -p "$D/var/packages/$1"; printf 'version="%s"\n' "$2" > "$D/var/packages/$1/INFO"; }
audit() { # audit NAME [args]; output goes to stdout
  shift
  SYNOLOGY_AUDIT_TEST_ROOT="$D" SYNOLOGY_AUDIT_TEST_PATH="$MOCK_BIN" sh "$SCRIPT" "$@" || true
}

base clean 7.4.1 90080 1
pkg FileStation 1.4.4-2221; pkg HyperBackup 4.2.2-4262
audit clean > "$OUTDIR/dsm-ok.txt"

base review 7.4.1 90080 1
pkg FileStation 1.4.4-2221; pkg Python2 2.7.18-1004; pkg QuickConnect 1.0.10-0187
printf '[global]\n\tmin protocol=NT1\n' > "$D/etc/samba/smb.conf"
printf 'USER PID COMMAND\nroot 9912 sshd: /usr/bin/sshd -D [listener]\n' > "$D/_ps"
printf 'ssh_port="8522"\n' > "$D/etc/synoinfo.conf"
audit review > "$OUTDIR/dsm-review.txt"

base vulnerable 7.2.2 72806 4
pkg PHP8.2 8.2.34-0100; pkg WebStation 4.0.0-0100; pkg WordPress 6.8.0-0001
audit vulnerable > "$OUTDIR/dsm-vulnerable.txt"
audit vulnerable --json > "$OUTDIR/dsm-vulnerable.json"

base indicators 7.3.2 86009 4
mkdir -p "$D/volume1/Documents"; : > "$D/volume1/Documents/budget.xlsx.c3rb3r"
audit indicators > "$OUTDIR/dsm-indicators.txt"

ls -1 "$OUTDIR"
