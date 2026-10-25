#!/usr/bin/env python3
"""Pinned, unprivileged native Kbuild driver. Never accesses a device."""
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'work'
LOGS = ROOT / 'reports' / 'logs'
MANIFEST = json.loads((ROOT / 'inputs' / 'manifest.json').read_text())
KERNEL = WORK / 'kernel'
ABI_KERNEL = WORK / 'kernel-abi-port'
ABI_OUT = WORK / 'build-abi-port'
ABI_PATCHES = (
    '0001-preserve-struct-net-move-gencursor-to-pernet.patch',
    '0002-nft-chain-nat-inet-family-ops-adapter.patch',
)
ABI_PATCHED_FILES = (
    'include/net/net_namespace.h',
    'include/net/netfilter/nf_tables.h',
    'net/netfilter/nf_tables_api.c',
    'net/netfilter/nf_tables_core.c',
    'net/netfilter/nft_chain_nat.c',
)

def require_hash(path, expected):
    got = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if got != expected:
        raise ValueError(f'SHA256 mismatch: {path}: {got} != {expected}')

def parse_config(text):
    result = {}
    for line in text.splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1)
            result[key] = value
        elif re.fullmatch(r'# CONFIG_\w+ is not set', line):
            result[line.split()[1]] = 'n'
    return result

def preserve_host_config(original, modified):
    prefixes = ('CONFIG_NF_CONNTRACK', 'CONFIG_NF_CT_', 'CONFIG_NF_NAT',
                'CONFIG_NF_DEFRAG', 'CONFIG_NETFILTER_NETLINK',
                'CONFIG_NETFILTER_SYNPROXY', 'CONFIG_NET_ACT_CT', 'CONFIG_NF_FLOW_TABLE')
    for key in original.keys() | modified.keys():
        if key.startswith(prefixes) and original.get(key, 'n') != modified.get(key, 'n'):
            raise ValueError(f'host configuration drift: {key}: {original.get(key, "n")} -> {modified.get(key, "n")}')

def environment():
    env = os.environ.copy()
    env['PATH'] = f'{WORK}/toolchain/bin:{WORK}/host/usr/bin:' + env['PATH']
    env['LD_LIBRARY_PATH'] = f'{WORK}/host/usr/lib64:' + env.get('LD_LIBRARY_PATH', '')
    env['BISON_PKGDATADIR'] = str(WORK / 'host/usr/share/bison')
    env['M4'] = str(WORK / 'host/usr/bin/m4')
    env['KBUILD_BUILD_TIMESTAMP'] = 'Thu Jan 1 00:00:00 UTC 1970'
    env['KBUILD_BUILD_USER'] = 'native-static-build'
    env['KBUILD_BUILD_HOST'] = 'isolated'
    return env

def run(name, command, cwd=None, env=None, required=True):
    LOGS.mkdir(parents=True, exist_ok=True)
    # Preserve every attempt, including successful repeat invocations.
    index = 1
    stem = name
    while (LOGS / (stem + '.log')).exists():
        index += 1
        stem = f'{name}-{index}'
    print(f'RUN {stem}: {shlex.join(map(str, command))}', flush=True)
    with (LOGS / (stem + '.log')).open('w') as stream:
        stream.write('$ ' + shlex.join(map(str, command)) + '\n')
        stream.write('cwd=' + str(cwd or Path.cwd()) + '\n')
        stream.flush()
        proc = subprocess.run(list(map(str, command)), cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
    (LOGS / (stem + '.status')).write_text(str(proc.returncode) + '\n')
    print(f'EXIT {proc.returncode}; {LOGS / (stem + ".log")}', flush=True)
    if required and proc.returncode:
        raise RuntimeError(f'{stem} failed: exit {proc.returncode}; see log')
    return proc.returncode

def validate_inputs():
    for name, digest in MANIFEST['inputs'].items():
        require_hash(ROOT / 'inputs' / name, digest)

def download(name, url, path, digest):
    if not path.exists():
        run(name, ['curl', '-fL', '--retry', '2', '--connect-timeout', '20', url, '-o', path])
    require_hash(path, digest)

def kernel_repository():
    configured = os.environ.get('KERNEL_SOURCE') or MANIFEST['kernel'].get('local_source')
    repository = Path(configured) if configured else WORK / 'kernel-git'
    return repository if repository.exists() else WORK / 'kernel-git'

def bootstrap():
    validate_inputs()
    WORK.mkdir(exist_ok=True)
    tc = MANIFEST['toolchain']
    download('clang-fetch', tc['url'], WORK / 'clang.tar.gz', tc['sha256'])
    if not (WORK / 'toolchain/bin/clang').exists():
        (WORK / 'toolchain').mkdir(exist_ok=True)
        run('clang-unpack', ['tar', 'xzf', WORK / 'clang.tar.gz', '-C', WORK / 'toolchain'])
    require_hash(WORK / 'toolchain/bin/clang', tc['clang_sha256'])
    packages = json.loads((ROOT / 'inputs/host-packages.json').read_text())
    for name, package in packages.items():
        rpm = WORK / (name + '.rpm')
        download('rpm-' + name, package['url'], rpm, package['sha256'])
        marker = WORK / 'host' / ('.' + name + '.extracted')
        if not marker.exists():
            marker.parent.mkdir(exist_ok=True)
            run('extract-' + name, ['bash', '-o', 'pipefail', '-c', 'rpm2cpio ' + shlex.quote(str(rpm)) + ' | cpio -idm --quiet'], cwd=marker.parent)
            marker.touch()
    run('host-tools', ['bash', '-e', '-c', 'flex --version; bison --version; bc --version; pahole --version; clang --version'], env=environment())
    vendor = WORK / 'vendor-src'
    pin = MANIFEST['vendor']
    for name, package in json.loads((ROOT / 'inputs/host-compat-packages.json').read_text()).items():
        rpm = WORK / ('compat-' + name + '.rpm')
        download('rpm-compat-' + name, package['url'], rpm, package['sha256'])
        destination = WORK / 'host-compat'
        destination.mkdir(exist_ok=True)
        marker = destination / ('.' + name + '.extracted')
        if not marker.exists():
            run('extract-compat-' + name, ['bash', '-o', 'pipefail', '-c', 'rpm2cpio ' + shlex.quote(str(rpm)) + ' | cpio -idm --quiet'], cwd=destination)
            marker.touch()
    if not vendor.exists():
        run('vendor-clone', ['git', 'clone', '--depth=1', '--filter=blob:none', '--sparse', '--branch', pin['branch'], pin['url'], vendor])
    current = subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip()
    if current != pin['commit']:
        run('vendor-pin-fetch', ['git', '-C', vendor, 'fetch', '--depth=1', 'origin', pin['commit']])
        run('vendor-pin-checkout', ['git', '-C', vendor, 'checkout', '--detach', pin['commit']])
    run('vendor-sparse', ['git', '-C', vendor, 'sparse-checkout', 'set', 'vendor/oplus/kernel', 'vendor/mediatek/kernel_modules'])
    if not (WORK / 'vendor').exists():
        (WORK / 'vendor').symlink_to(vendor / 'vendor', target_is_directory=True)
    source = kernel_repository()
    if not source.exists():
        run('kernel-clone', ['git', 'clone', '--filter=blob:none', '--no-checkout', MANIFEST['kernel']['url'], source])
    pin = MANIFEST['kernel']['commit']
    if source == WORK / 'kernel-git':
        run('kernel-pin-fetch', ['git', '-C', source, 'fetch', '--depth=1', 'origin', pin])
        run('kernel-pin-checkout', ['git', '-C', source, 'checkout', '--detach', pin])
    if subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() != pin:
        raise ValueError('kernel source HEAD mismatch: expected ' + pin)
    if not KERNEL.exists():
        KERNEL.mkdir()
        run('source-snapshot', ['bash', '-o', 'pipefail', '-c', 'git -C ' + shlex.quote(str(source)) + ' archive ' + pin + ' | tar xf - -C ' + shlex.quote(str(KERNEL))])
    # Hash tracked snapshot files against the pinned Git tree, including symlink targets.
    tree = subprocess.check_output(['git', '-C', str(source), 'ls-tree', '-rz', pin])
    mismatches = []
    for row in tree.split(b'\0'):
        if not row:
            continue
        meta, name = row.split(b'\t', 1)
        mode, kind, object_id = meta.split()
        if kind != b'blob':
            continue
        file = KERNEL / os.fsdecode(name)
        data = os.fsencode(os.readlink(file)) if mode == b'120000' else file.read_bytes()
        got = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if got != object_id.decode():
            mismatches.append(os.fsdecode(name))
    if mismatches:
        raise ValueError('source snapshot mismatch: ' + repr(mismatches))
    (ROOT / 'reports/source-check.json').write_text(json.dumps({'commit': pin, 'tracked_files_checked': len(tree.split(b'\0')) - 1, 'mismatches': mismatches}, indent=2) + '\n')

def validate_source_tree(kernel, source, pin):
    tree = subprocess.check_output(['git', '-C', str(source), 'ls-tree', '-rz', pin])
    mismatches = []
    tracked = set()
    for row in tree.split(b'\0'):
        if not row:
            continue
        meta, name = row.split(b'\t', 1)
        mode, kind, object_id = meta.split()
        if kind != b'blob':
            continue
        relative = os.fsdecode(name)
        tracked.add(relative)
        file = kernel / relative
        try:
            data = os.fsencode(os.readlink(file)) if mode == b'120000' else file.read_bytes()
        except OSError:
            mismatches.append(relative)
            continue
        got = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if got != object_id.decode():
            mismatches.append(relative)
    unexpected = []
    for directory, dirnames, filenames in os.walk(kernel):
        dirnames[:] = [name for name in dirnames if name not in ('.git',)]
        for name in filenames:
            relative = os.path.relpath(os.path.join(directory, name), kernel)
            if relative not in tracked:
                unexpected.append(relative)
    return sorted(mismatches), sorted(unexpected), len(tracked)


def check_exact_patched_files(kernel, source, pin, patches):
    with tempfile.TemporaryDirectory(prefix='nft-abi-source-') as tmp:
        expected = Path(tmp)
        for name in ABI_PATCHED_FILES:
            destination = expected / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(subprocess.check_output(['git', '-C', str(source), 'show', pin + ':' + name]))
        for patch in patches:
            subprocess.run(['patch', '-p1', '--no-backup-if-mismatch', '-i', str(ROOT / 'patches' / patch)],
                           cwd=expected, check=True, stdout=subprocess.DEVNULL)
        return [name for name in ABI_PATCHED_FILES
                if (kernel / name).read_bytes() != (expected / name).read_bytes()]


def validate_abi_port_source():
    source = kernel_repository()
    pin = MANIFEST['kernel']['commit']
    manifest = json.loads((ROOT / 'patches/manifest.json').read_text())
    patches = list(manifest['patches'])
    if patches != list(ABI_PATCHES):
        raise ValueError('ABI patch list/order mismatch')
    for name, info in manifest['patches'].items():
        require_hash(ROOT / 'patches' / name, info['sha256'])
    mismatches, unexpected, checked = validate_source_tree(ABI_KERNEL, source, pin)
    unexpected = [name for name in unexpected if name not in ABI_PATCHED_FILES]
    allowed_mismatches = [name for name in mismatches if name in ABI_PATCHED_FILES]
    if len(allowed_mismatches) != len(ABI_PATCHED_FILES):
        raise ValueError('patched source does not contain every intended drift')
    mismatches = [name for name in mismatches if name not in ABI_PATCHED_FILES]
    exact_mismatches = check_exact_patched_files(ABI_KERNEL, source, pin, patches)
    report = {'commit': pin, 'tracked_files_checked': checked, 'mismatches': mismatches + exact_mismatches,
              'unexpected_files': unexpected, 'patched_files': allowed_mismatches,
              'patches': patches, 'patch_sha256': {name: info['sha256'] for name, info in manifest['patches'].items()}}
    (ROOT / 'reports/abi-port-source.json').write_text(json.dumps(report, indent=2) + '\n')
    if mismatches or exact_mismatches or unexpected:
        raise ValueError('ABI-port source mismatch or unexpected files')
    pristine_mismatches, _, _ = validate_source_tree(KERNEL, source, pin)
    if pristine_mismatches:
        raise ValueError('pristine source changed: ' + repr(pristine_mismatches))
    return report


def bootstrap_abi_port():
    bootstrap()
    manifest = json.loads((ROOT / 'patches/manifest.json').read_text())
    if not ABI_KERNEL.exists():
        ABI_KERNEL.mkdir()
        run('abi-port-source-snapshot', ['bash', '-o', 'pipefail', '-c',
            'git -C ' + shlex.quote(str(kernel_repository())) + ' archive ' +
            MANIFEST['kernel']['commit'] + ' | tar xf - -C ' + shlex.quote(str(ABI_KERNEL))])
        for name in manifest['patches']:
            require_hash(ROOT / 'patches' / name, manifest['patches'][name]['sha256'])
            run('abi-port-patch-' + name, ['patch', '-p1', '--no-backup-if-mismatch',
                '-i', ROOT / 'patches' / name], cwd=ABI_KERNEL)
    return validate_abi_port_source()


def prepare_abi_port():
    bootstrap_abi_port()
    if ABI_OUT.exists():
        raise ValueError('refusing to overwrite existing ABI-port build output; run build.py')
    ABI_OUT.mkdir()
    original = parse_config((ROOT / 'inputs/target.config').read_text())
    fragment = parse_config((ROOT / 'configs/nftables.fragment').read_text())
    shutil.copyfile(ROOT / 'inputs/target.config', ABI_OUT / '.config')
    options = {'CONFIG_LOCALVERSION': '"-android14-oki-xiaoxiaow"', 'CONFIG_LOCALVERSION_AUTO': 'n', **fragment}
    command = [ABI_KERNEL / 'scripts/config', '--file', ABI_OUT / '.config']
    for key, value in options.items():
        if value == 'n': command.extend(['--disable', key[7:]])
        elif value == 'm': command.extend(['--module', key[7:]])
        elif value == 'y': command.extend(['--enable', key[7:]])
        else: command.extend(['--set-str', key[7:], value.strip('"')])
    run('abi-port-config', command)
    run('abi-port-olddefconfig', make_command(ABI_OUT, 'olddefconfig'), env=environment())
    current = parse_config((ABI_OUT / '.config').read_text())
    preserve_host_config(original, current)
    required = {'CONFIG_MODVERSIONS':'y', 'CONFIG_CFI_CLANG':'y', 'CONFIG_LTO_NONE':'y',
                'CONFIG_DEBUG_INFO_BTF':'y', 'CONFIG_DEBUG_INFO_BTF_MODULES':'y',
                'CONFIG_MODULE_SIG_FORCE':'n', **options}
    for key, value in required.items():
        if current.get(key, 'n') != value:
            raise ValueError(f'ABI-port option not retained: {key}: {value} != {current.get(key)}')
    run('abi-port-modules-prepare', make_command(ABI_OUT, 'modules_prepare'), env=environment())
    if (ABI_OUT / 'include/config/kernel.release').read_text().strip() != MANIFEST['target_release']:
        raise ValueError('ABI-port kernel.release mismatch')
    shutil.copyfile(ROOT / 'inputs/Module.symvers', ABI_OUT / 'Module.symvers')
    require_hash(ABI_OUT / 'Module.symvers', MANIFEST['inputs']['Module.symvers'])


def finalize_artifacts():
    """Build the host-interface probe and derive metadata from actual modules."""
    output = ROOT / 'output/abi-port'
    artifacts = json.loads((ROOT / 'reports/abi-port-artifact-sha256.json').read_text())
    for name, digest in artifacts.items():
        require_hash(output / name, digest)
    os.environ['NFTABLES_KERNEL'] = str(ABI_KERNEL)
    probe = WORK / 'layout-abi-port'
    probe.mkdir(exist_ok=True)
    shutil.copyfile(ROOT / 'scripts/layout-probe.c', probe / 'probe.c')
    (probe / 'Makefile').write_text('obj-m := probe.o\n')
    run('abi-port-layout-probe', make_command(ABI_OUT, 'M=' + str(probe), 'probe.o'), env=environment())
    dependencies = []
    for name in sorted(artifacts):
        imported = subprocess.check_output(['modinfo', '-F', 'depends', str(output / name)], text=True).strip()
        providers = sorted(filter(None, imported.split(',')))
        if any(provider + '.ko' not in artifacts for provider in providers):
            raise ValueError(f'{name}: module dependency not built: {providers}')
        dependencies.append(name + ':' + ''.join(' ' + provider + '.ko' for provider in providers))
    (output / 'modules.dep').write_text('\n'.join(dependencies) + '\n')
    config = (ABI_OUT / '.config').read_text()
    (ROOT / 'reports/abi-port.config').write_text(config)
    (ROOT / 'reports/abi-port-config.diff').write_text(''.join(difflib.unified_diff(
        (ROOT / 'inputs/target.config').read_text().splitlines(True), config.splitlines(True),
        fromfile='inputs/target.config', tofile='abi-port.config')))
    identity_paths = [probe / 'probe.o', probe / 'probe.c', ABI_OUT / '.config',
                      ROOT / 'reports/abi-port-built-module-exports.symvers']
    identity_paths += [ABI_KERNEL / name for name in ABI_PATCHED_FILES]
    identities = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in identity_paths}
    (ROOT / 'reports/abi-port-layout-inputs.json').write_text(json.dumps(identities, indent=2) + '\n')


def undefined_symbols(module):
    output = subprocess.run(['llvm-nm', '--undefined-only', '--format=posix', str(module)],
                            check=True, capture_output=True, text=True).stdout
    return {line.split()[0] for line in output.splitlines() if line.split()}


def kbuild_jobs():
    value = os.environ.get('JOBS', '2')
    if value not in ('1', '2'):
        raise ValueError('JOBS must be 1 or 2 on this EL build host; got ' + repr(value))
    return value

def make_command(out, *args):
    return ['make', '-C', os.environ.get('NFTABLES_KERNEL', str(KERNEL)), 'O=' + str(out), 'ARCH=arm64', 'LLVM=1', 'LLVM_IAS=1', 'LOCALVERSION=', 'HOSTCC=gcc -std=gnu11 -isystem ' + str(WORK / 'host-compat/usr/include') + ' -I' + str(WORK / 'host/usr/include'), 'HOSTCXX=g++', '-j' + kbuild_jobs(), *args]

def prepare():
    bootstrap()
    original = parse_config((ROOT / 'inputs/target.config').read_text())
    fragment = parse_config((ROOT / 'configs/nftables.fragment').read_text())
    for variant in ('baseline', 'nftables'):
        out = WORK / ('build-' + variant)
        out.mkdir(exist_ok=True)
        shutil.copyfile(ROOT / 'inputs/target.config', out / '.config')
        options = {'CONFIG_LOCALVERSION': '"-android14-oki-xiaoxiaow"', 'CONFIG_LOCALVERSION_AUTO': 'n'}
        if variant == 'nftables':
            options.update(fragment)
        command = [KERNEL / 'scripts/config', '--file', out / '.config']
        for key, value in options.items():
            if value == 'n':
                command.extend(['--disable', key[7:]])
            elif value == 'm':
                command.extend(['--module', key[7:]])
            elif value == 'y':
                command.extend(['--enable', key[7:]])
            else:
                command.extend(['--set-str', key[7:], value.strip('"')])
        run('config-' + variant, command)
        run('olddefconfig-' + variant, make_command(out, 'olddefconfig'), env=environment())
        current = parse_config((out / '.config').read_text())
        preserve_host_config(original, current)
        required = {'CONFIG_MODVERSIONS':'y', 'CONFIG_CFI_CLANG':'y', 'CONFIG_LTO_NONE':'y', 'CONFIG_DEBUG_INFO_BTF':'y', 'CONFIG_DEBUG_INFO_BTF_MODULES':'y', 'CONFIG_MODULE_SIG_FORCE':'n', **options}
        for key, value in required.items():
            if current.get(key, 'n') != value:
                raise ValueError(f'{variant}: option not retained: {key}: expected {value}, got {current.get(key)}')
        shutil.copyfile(out / '.config', ROOT / 'reports' / (variant + '.config'))
        diff = ''.join(difflib.unified_diff((ROOT / 'inputs/target.config').read_text().splitlines(True), (out / '.config').read_text().splitlines(True), fromfile='inputs/target.config', tofile=variant + '.config'))
        (ROOT / 'reports' / (variant + '-config.diff')).write_text(diff)
        run('modules-prepare-' + variant, make_command(out, 'modules_prepare'), env=environment())
        release = (out / 'include/config/kernel.release').read_text().strip()
        if release != MANIFEST['target_release']:
            raise ValueError('kernel.release mismatch: ' + release)
        shutil.copyfile(ROOT / 'inputs/Module.symvers', out / 'Module.symvers')
    run('toolchain-identity', ['bash', '-c', 'clang --version; ld.lld --version; pahole --version; gcc --version'], env=environment())

if __name__ == '__main__':
    try:
        {'prepare': prepare}[sys.argv[1]]()
    except Exception as error:
        print('ERROR:', error, file=sys.stderr)
        sys.exit(1)
