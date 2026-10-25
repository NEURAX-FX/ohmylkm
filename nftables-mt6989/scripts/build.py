#!/usr/bin/env python3
"""Build selected existing Kbuild targets, preserving modpost errors unchanged."""
import json
import shutil
import sys
from pathlib import Path
import buildlib as b

import os
os.environ['NFTABLES_KERNEL'] = str(b.ABI_KERNEL)
b.kbuild_jobs()
if len(sys.argv) > 1 and sys.argv[1] == 'prepare-only':
    if b.ABI_OUT.exists():
        sys.exit('refusing to overwrite existing ABI-port output')
    b.prepare_abi_port()
    sys.exit(0)
out = b.ABI_OUT
if out.exists():
    b.bootstrap_abi_port()
else:
    b.prepare_abi_port()
b.validate_inputs()
b.require_hash(b.WORK / 'toolchain/bin/clang', b.MANIFEST['toolchain']['clang_sha256'])
if (out / 'include/config/kernel.release').read_text().strip() != b.MANIFEST['target_release']:
    sys.exit('kernel.release mismatch')
b.require_hash(out / 'Module.symvers', b.MANIFEST['inputs']['Module.symvers'])
original = b.parse_config((b.ROOT / 'inputs/target.config').read_text())
current = b.parse_config((out / '.config').read_text())
b.preserve_host_config(original, current)
for key, value in b.parse_config((b.ROOT / 'configs/nftables.fragment').read_text()).items():
    if current.get(key, 'n') != value:
        sys.exit(f'configuration mismatch: {key}')
for key in ('CONFIG_DEBUG_INFO_BTF_MODULES', 'CONFIG_CFI_CLANG', 'CONFIG_MODVERSIONS', 'CONFIG_LTO_NONE'):
    if current.get(key) != 'y':
        sys.exit(f'ABI option missing: {key}')
exports = b.ROOT / 'reports/abi-port-built-module-exports.symvers'
results = []
output = b.ROOT / 'output/abi-port'
output.mkdir(parents=True, exist_ok=True)
if any(output.iterdir()):
    sys.exit('refusing to mix ABI-port output with stale or unexpected files')
exports.write_text('')
(b.ROOT / 'reports/abi-port-build-results.json').write_text('[]\n')
targets = [('net/netfilter', name) for name in (
    'nf_tables', 'nft_ct', 'nft_nat', 'nft_chain_nat', 'nft_masq', 'nft_limit',
    'nft_redir', 'nft_log', 'nft_fib', 'nft_reject')]
targets += [(f'net/{family}/netfilter', f'nft_{expr}_{family}')
            for family in ('ipv4', 'ipv6') for expr in ('fib', 'reject')]
targets += [('net/netfilter', 'nft_fib_inet'), ('net/netfilter', 'nft_reject_inet')]
for directory, name in targets:
    source = b.ABI_KERNEL / directory
    args = ['M=' + str(source), name + '.ko']
    if name != 'nf_tables':
        args.append('KBUILD_EXTRA_SYMBOLS=' + str(exports))
    code = b.run('build-' + name, b.make_command(out, *args), env=b.environment(), required=False)
    results.append({'module': name + '.ko', 'exit_code': code, 'source_directory': directory})
    if code == 0:
        shutil.copyfile(source / (name + '.ko'), output / (name + '.ko'))
        # These are real modpost-generated exports, never substitutes for host CRCs.
        lines = (source / 'Module.symvers').read_text().splitlines(True)
        with exports.open('a') as stream:
            stream.writelines(line for line in lines if Path(line.split('\t')[2]).name == name)
    else:
        (output / (name + '.ko')).unlink(missing_ok=True)
        if name == 'nf_tables':
            (b.ROOT / 'reports/abi-port-build-results.json').write_text(json.dumps(results, indent=2) + '\n')
            sys.exit('nf_tables core failed; dependent module builds suppressed')
import hashlib
hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
          for path in sorted(output.iterdir()) if path.is_file()}
(b.ROOT / 'reports/abi-port-artifact-sha256.json').write_text(json.dumps(hashes, indent=2) + '\n')
(b.ROOT / 'reports/abi-port-build-results.json').write_text(json.dumps(results, indent=2) + '\n')
print(json.dumps(results, indent=2))
if not any(row['exit_code'] for row in results):
    b.finalize_artifacts()
# Partial success is intentionally nonzero; never suppress failed native symbols.
sys.exit(1 if any(row['exit_code'] for row in results) else 0)
