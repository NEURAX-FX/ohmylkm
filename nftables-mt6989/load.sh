#!/system/bin/sh
# MT6989 nftables LKM loader. Run manually on the device via adb/root shell.
# Usage: sh load.sh [--dry-run]
# Default: show live release/vermagic and wait for explicit "y" before loading.

set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

fail() { echo "ERROR: $*" >&2; exit 1; }

# --- environment checks -----------------------------------------------------
[ -e /proc/sys/kernel/modprobe ] || fail "not Linux"
[ "$(id -u)" = 0 ] || fail "must run as root"

LIVE_RELEASE=$(uname -r)
case "$LIVE_RELEASE" in
  6.1.115-android14-oki-xiaoxiaow) ;;                 # expected real release
  6.1.115-android14-11-g2d2543bebccf-ab12401295) ;;  # known SUSFS-spoofed release
  *) fail "unexpected running release: $LIVE_RELEASE";;
esac

# Modules were built for vermagic:
# 6.1.115-android14-oki-xiaoxiaow SMP preempt mod_unload modversions aarch64
# Signature/lockdown policy can still reject them; insmod failures are final.
[ "${MODULES_DISABLED:-}" = "1" ] && fail "module loading globally disabled"

# --- fixed load order -------------------------------------------------------
ORDER="nf_tables nft_ct nft_nat nft_chain_nat nft_masq nft_limit nft_redir nft_log nft_fib nft_reject nft_fib_ipv4 nft_reject_ipv4 nft_fib_ipv6 nft_reject_ipv6 nft_reject_inet nft_fib_inet"

echo "live release : $LIVE_RELEASE"
echo "modules.dep  :"
cat "$HERE/modules.dep" 2>/dev/null || fail "modules.dep missing next to load.sh"

for m in $ORDER; do
  [ -f "$HERE/$m.ko" ] || fail "missing $HERE/$m.ko"
done

[ "$DRY" = 1 ] && { echo "dry run ok, no module loaded"; exit 0; }

echo
echo "This will load 16 kernel modules on the running phone."
printf 'Type y to continue: '
read ans
[ "$ans" = "y" ] || { echo "aborted"; exit 1; }

for m in $ORDER; do
  echo "insmod $HERE/$m.ko"
  insmod "$HERE/$m.ko" || fail "insmod $m.ko failed (see dmesg; do not force-load)"
done

echo
echo "Loaded modules:"
cat /proc/modules | grep -E '^(nf_tables|nft_)' || true
echo "Done. No ruleset was installed and no network configuration was changed."
