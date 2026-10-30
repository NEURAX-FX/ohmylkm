# nftables-mt6989

Source-compatible `nf_tables`/`nft_*` kernel modules for MediaTek MT6989
(OnePlus Ace 5 Racing), built from the public OnePlus Linux 6.1 source with
Android Clang r487747c.

The target device kernel was built with `CONFIG_NF_TABLES=n`. Loading stock
upstream modules would fail without these source adaptations:

1. Enabling `NF_TABLES` normally inserts `netns_nftables` into `struct net`,
   shifting host-owned fields. The module copy keeps the host layout and moves
   the nft generation cursor into the existing private per-net storage.
2. The target kernel does not export
   `nf_nat_inet_register_fn`/`nf_nat_inet_unregister_fn`. The inet NAT chain
   adapter uses the exported IPv4/IPv6 registration functions with stable
   per-chain hook-ops copies, correct rollback and unregistration.
3. `NF_FLOW_TABLE=m` also changes `struct net` and TCP/UDP conntrack
   namespace layouts. Flow statistics and offload timeouts are kept in the
   flowtable module's own per-net allocation instead; host conntrack is not
   rebuilt. The core exports its real `nf_tables_net_id` for the flow-offload
   expression's private generation access.

No host kernel code is patched at runtime, no symbol CRC is forged and no
module is force-loaded.

## Pinned inputs

| Item | Value |
|---|---|
| Kernel source | `OnePlusOSS/android_kernel_oneplus_mt6989` @ `b1ea2c8ce2ef0f73927a593aa450f88143e3584a` |
| Vendor tree | `OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_mt6989` @ `e7320c9131c8fa539dc0e3899e7c81eba901da21` |
| Compiler | Android Clang r487747c / 17.0.2 |
| Release | `6.1.115-android14-oki-xiaoxiaow` |
| Vermagic | `6.1.115-android14-oki-xiaoxiaow SMP preempt mod_unload modversions aarch64` |

`inputs/manifest.json` contains URLs, commit IDs and SHA256 pins.

The target configuration `inputs/target.config` is included from the public
reference project. These device-specific inputs are intentionally **not**
committed and must be supplied locally:
- `inputs/Module.symvers` — original target export table
- `inputs/boot-image/target.btf`, `target.kallsyms`, `Image` — needed only by
  the full ABI verifier, not by compilation

`target.config` and `Module.symvers` hashes are pinned in the manifest. Keep
the originals unchanged; a table rebuilt from mismatched source is not a
substitute.

## Build

Requires `make`, `gcc/g++`, `git`, `curl`, `tar`, `patch`, `rpm2cpio`, `cpio`
and Python 3. All other build dependencies and the compiler are pinned and
downloaded into `work/` by the scripts; no root access is used.

```sh
export KERNEL_SOURCE=/path/to/android_kernel_oneplus_mt6989   # pinned commit
JOBS=2 ./scripts/prepare.sh
JOBS=2 ./scripts/build.sh
```

`prepare.sh` validates inputs, creates the isolated patched build, runs
`olddefconfig` and `modules_prepare`, and stores the original export table.
`build.sh` builds the selected modules with native Kbuild and `-j2`.

**Concurrency is deliberately capped.** `JOBS` defaults to `2` and only `1`
or `2` is accepted; higher values abort before invoking make. The layout probe
uses `pahole -j1`.

Generated artifacts land in `output/abi-port/`. Build logs and exact commands
land in `reports/logs/`. The scripts refuse to overwrite a non-empty existing
output directory; move or remove prior generated output first.

Modules built:

`nf_tables`, `nft_ct`, `nft_nat`, `nft_chain_nat`, `nft_masq`, `nft_limit`,
`nft_redir`, `nft_log`, `nft_fib`, `nft_reject`, `nft_fib_ipv4`,
`nft_reject_ipv4`, `nft_fib_ipv6`, `nft_reject_ipv6`, `nft_fib_inet`,
`nft_reject_inet`, `nf_flow_table`, `nf_flow_table_inet`, `nft_flow_offload`.

## Software flow offloading

The new 19-module build includes the full fw4 inet flowtable path:
`nf_flow_table.ko` -> `nf_flow_table_inet.ko` -> `nft_flow_offload.ko`.
The source Kconfig calls the expression a hardware-offload module, but it is
also needed for software `flow add`; hardware acceleration is a separate
flowtable flag and is not enabled by this package.

Both TCP and UDP offload idle timeouts retain the upstream 30-second defaults
in module-private per-net storage. The host was built without the associated
sysctl fields, so `nf_flowtable_tcp_timeout`/`nf_flowtable_udp_timeout` are not
exposed by this port. Existing host conntrack timeouts remain unchanged.
`NF_FLOW_TABLE_PROCFS=n` keeps optional flowtable proc statistics disabled.

Loading modules only makes the feature available. In ImmortalWrt, enable
firewall4 software flow offloading separately; leave hardware offloading off
unless the actual host drivers have been independently validated. No nft
rules, UCI settings or device interfaces are changed by the loader.

The previous working basic 16-module artifacts were retained locally under
`output/basic-16/`. The new expression imports a new genuine core export:
use the new `nf_tables.ko` with it, not the previous core alone. New software
flow packet-path behavior has not been exercised on the phone by these tools.

## Verification

`scripts/verify.sh` is a fail-closed static verifier. It parses real ELF
relocations and export CRCs, checks vermagic/AArch64/GPL/license/namespaces,
version records, provider resolution, dependency graph, `__this_module` size,
and compares a fresh Kbuild/DWARF probe against the supplied target BTF. It
also compares named host KCFI type words against the supplied target Image.

It requires the private target inputs noted above and the local toolchain.
Missing tools or missing evidence fail; they are never skipped. It does not
load modules.

```sh
./scripts/verify.sh
python3 -m unittest discover -s tests -v
```

The reference build passed these checks, but that result is bound to the
private target image and build hashes. It is not a runtime safety claim.
Module `.BTF` sections are absent because the original vmlinux ELF is not
available; the target loader tolerates this.

## Magisk module

The flashable module source lives in `magisk/nftables-mt6989/`. It contains:

- `module.prop`
- `customize.sh`
- `post-fs-data.sh` — loads 19 modules in dependency order at `post-fs-data`
- `META-INF/com/google/android/update-binary` — standard Magisk installer hook
- `system/lib/modules/*.ko` (populate from `output/abi-port/`)

`post-fs-data.sh` skips modules already present, is idempotent per boot via
`/proc/sys/kernel/random/boot_id`, logs to
`/data/local/tmp/nftables-mt6989.log`, and never blocks boot. It also refuses
to continue when `modules_disabled=1`. It does not install any firewall rules.

Build the zip after copying the desired modules:

```sh
cp output/abi-port/*.ko magisk/nftables-mt6989/system/lib/modules/
cd magisk/nftables-mt6989
zip -r -X ../nftables-mt6989-magisk-v1.1-flow-offload.zip module.prop customize.sh post-fs-data.sh META-INF system
```

The ZIP is flashable only when Magisk is installed; its standard
`update-binary` hook delegates to `/data/adb/magisk/util_functions.sh`.
Installing through the Magisk/KernelSU app also works.

Install through Magisk/KernelSU and reboot. The repository itself does not
ship compiled modules or zip files.

For a manual test, `load.sh` loads the same modules from a directory in an
adb/root shell. It asks for confirmation unless run with `--dry-run`.

## Limits

- Verified against the currently supplied target image only. It does not
  identify which image is running on a particular phone.
- Full nested-type compatibility, every KCFI callback boundary, module
  signing/SELinux policy and load/unload behavior are not proven by static
  checks.
- KernelSU/SUSFS options present in the downstream target config are absent
  from the public source and are removed by `olddefconfig`; this is not a
  byte-identical rebuild of the vendor kernel.
- Firewall4 rulesets, IPv4 MASQUERADE/conntrack, LAN→WAN forwarding, DNS/DHCP
  handling and container network namespaces were not exercised by this
  project's build tooling.

Do not force-load a mismatched module.
