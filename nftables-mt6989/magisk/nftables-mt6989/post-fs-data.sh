#!/system/bin/sh
# Loads the adapted nftables modules once, as early as Magisk allows.
# Runs in Magisk's post-fs-data stage: /data is decrypted, before system_server,
# so these modules are available to zygote, netd and every network namespace.

MODDIR=${0%/*}
MODID=nftables-mt6989
LOG=/data/local/tmp/$MODID.log
MARK=/data/adb/$MODID/.loaded

mkdir -p /data/adb/$MODID 2>/dev/null
[ -n "${MODDIR:-}" ] || MODDIR=/data/adb/modules/$MODID

log() { echo "[$(date '+%H:%M:%S')] $*" >> "$LOG" 2>/dev/null; }

# Only one load per boot: post-fs-data runs once, but keep it idempotent for
# manual/toggle runs and for modules restarted by Magisk's "reload".
if [ -f "$MARK" ] && [ "$(cat "$MARK" 2>/dev/null)" = "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" ]; then
  log "already loaded this boot"
  exit 0
fi

: > "$LOG"
log "post-fs-data start, running release: $(uname -r)"

# Module loading can be disabled by policy; report instead of silently failing.
if [ "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo 0)" = "1" ]; then
  log "ERROR: modules_disabled=1, cannot load"
  exit 0
fi

# Core first, then leaves; this is the verified dependency order
# (FIB: common -> ipv4/ipv6 -> inet, REJECT: common -> family/inet).
ORDER="nf_tables nft_ct nft_nat nft_chain_nat nft_masq nft_limit nft_redir nft_log nft_fib nft_reject nft_fib_ipv4 nft_reject_ipv4 nft_fib_ipv6 nft_reject_ipv6 nft_reject_inet nft_fib_inet"

fail=0
for m in $ORDER; do
  ko="$MODDIR/system/lib/modules/$m.ko"
  if [ ! -f "$ko" ]; then
    log "ERROR: missing $m.ko"
    fail=1
    continue
  fi
  # Skip modules already present (e.g. loaded by init or a previous run).
  if [ -d "/sys/module/$m" ]; then
    log "skip $m (already loaded)"
    continue
  fi
  if insmod "$ko" 2>>"$LOG"; then
    log "loaded $m"
  else
    log "ERROR: insmod $m failed (see dmesg; not force-loaded)"
    fail=1
  fi
done

if [ "$fail" = 0 ]; then
  cat /proc/sys/kernel/random/boot_id > "$MARK" 2>/dev/null
  log "all modules loaded"
else
  log "one or more modules failed; check dmesg and $LOG"
fi

# Never block boot: Magisk's post-fs-data has a hard timeout and failure here
# would only delay the rest of the boot process.
exit 0
