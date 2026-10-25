# Native MT6989 nftables Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: executing-plans. Execute inline, no commits and no device access.

**Goal:** Build source-native nftables modules and rigorously report static compatibility limits for the supplied MT6989 target.

**Architecture:** Immutable copied ABI inputs feed an isolated source snapshot and O= build outputs. Native Kbuild produces core first and selected firewall4 dependencies incrementally. A fail-closed ELF verifier and original/modified configuration layout probes gate compatibility claims.

**Tech Stack:** Linux 6.1.115 arm64 Kbuild, Android Clang r487747c, shell, Python.

**Spec:** User assignment and subsequent host-owned-layout ABI review instruction in this session.

## Global Constraints
- No commits/push, module loading, device/boot/SELinux/security-policy/kernel-memory access.
- Preserve original source/config/symvers. Use recovered original symbol table, never fabricate CRCs or suppress unresolved symbols.
- Release 6.1.115-android14-oki-xiaoxiaow; expected struct module size 1088.
- Auditor owns reports/abi-input-evidence.md and .json exclusively.

## Review Focus
- Source/input drift must hard-fail before building (negative hash test).
- olddefconfig must retain BTF_MODULES/CFI/MODVERSIONS/LTO and selected functionality (real prepare assertions).
- NF_TABLES must not silently shift host-owned layouts (paired record-layout comparison).
- Every strong import needs provider, CRC, license and namespace checks; dependency cycles must fail (verifier negative tests).
- Missing target Image/BTF must remain explicit and must never become a runtime-safety claim.

### Task 1: Inputs and feasibility
- [ ] Snapshot and hash original config/symvers; inspect source Kconfig/Makefiles and namespace storage.
- [ ] Pin kernel/reference/vendor/toolchain identities and install user-local prerequisites.
- [ ] Create tests for immutable input validation, execute RED, implement prepare entrypoint and execute actual prepare.

### Task 2: Source-native builds and paired layout evidence
- [ ] Build core nf_tables.ko with original target CRCs through native Kbuild; retain log/status.
- [ ] Incrementally build CT, NAT (both nft_nat/nft_chain_nat), masq, limit, reject/fib family dependencies, log and preserve all valid artifacts.
- [ ] Probe original and modified host-interface layouts and struct module; retain raw member layouts and comparison.

### Task 3: Static verification and handoff
- [ ] Write verifier negative tests first; execute RED; implement strict verifier and run tests GREEN.
- [ ] Run real build.sh and verify.sh; retain full logs, statuses, modules.dep/load order and ABI risks.
- [ ] Write README, ABI/symbol/build reports and exact provenance/config diff; workflow only if genuinely reproducible.
- [ ] Dispatch fresh final reviewer, fix important findings with regression evidence, retain final ledger.
