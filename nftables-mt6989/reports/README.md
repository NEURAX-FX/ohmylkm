# Reports

These files describe the reference build against a locally supplied target
kernel image:

- `abi-report.md` — host layout and KCFI checks
- `symbol-report.md` — export/CRC/dependency evidence
- `build-report.md` — exact native build and verification results
- `plan.md` — implementation plan and scope decisions

The target image, recovered BTF/kallsyms, original `Module.symvers`, raw logs
and generated binaries are intentionally not published. The reports therefore
document observed results but are not independently reproducible from this
repository alone.

The scripts remain the source of truth: `scripts/verify.sh` fails closed when
the required target inputs or tools are absent. A green reference run is
static evidence, not proof that loading the modules or running firewall4/NAT
is safe on a particular device.
