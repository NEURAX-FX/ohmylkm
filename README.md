# ohmylkm

Workspace for building and packaging Android kernel modules for MediaTek
MT6989 (OnePlus Ace 5 Racing), based on the public OnePlus Linux 6.1 source.

The current project is **`nftables-mt6989`**: native `nf_tables`/`nft_*`
kernel modules for a target kernel that was built with `CONFIG_NF_TABLES=n`,
plus a Magisk packaging layout and loader scripts.

## Contents

| Path | Purpose |
|---|---|
| `nftables-mt6989/` | Source-compatible nftables LKM project |
| `nftables-mt6989/patches/` | Two required source patches (per-net generation state, inet NAT adapter) |
| `nftables-mt6989/configs/` | Kbuild configuration fragment |
| `nftables-mt6989/scripts/` | Pinned build, probe and verification tooling |
| `nftables-mt6989/tests/` | Regression tests for scripts and generated ELF metadata |
| `nftables-mt6989/magisk/` | Magisk module source; `post-fs-data.sh` loads the modules |
| `nftables-mt6989/load.sh` | Manual one-shot loader for adb/root shell |

## Not included

This repository intentionally does **not** contain device-private or
build-specific data:

- `boot.img` and anything recovered from it (`Image`, BTF, kallsyms)
- the original target `Module.symvers`
- compiled `.ko` files, `.tar.gz` archives and Magisk zips
- `work/`, `output/` and `reports/logs/`

The target kernel config (`inputs/target.config`) and the original exported
symbol table (`inputs/Module.symvers`) are required to reproduce a binary
match. Their pinned SHA256 values are in `nftables-mt6989/inputs/manifest.json`;
supply your own copies at those paths before running `prepare.sh`. Never
replace them with a symbol table rebuilt from different source.

## Quick start

See `nftables-mt6989/README.md` for exact build, verification and Magisk
packaging instructions. In short:

```sh
export KERNEL_SOURCE=/path/to/android_kernel_oneplus_mt6989  # pinned commit
cd nftables-mt6989
JOBS=2 ./scripts/prepare.sh
JOBS=2 ./scripts/build.sh
./scripts/verify.sh          # needs the local target BTF/Image inputs
```

Kbuild concurrency is deliberately capped at 2 on this project; `JOBS` may be
`1` or `2` only.

## Safety scope

The build and verification scripts do not load modules, write boot partitions,
change SELinux/network policy or touch kernel memory. A successful static
check is not a runtime safety guarantee. The Magisk loader is opt-in and only
runs from `post-fs-data.sh` after explicit installation and reboot.
