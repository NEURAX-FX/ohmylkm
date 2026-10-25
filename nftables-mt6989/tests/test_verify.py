#!/usr/bin/env python3
"""Consumer-visible tests for the independent ABI-port verifier."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import verify as v  # noqa: E402

VERMAGIC = v.EXPECTED_VERMAGIC
MODULE_LAYOUT_CRC = 0xEA759D7F
HOST = {
    'module_layout': (MODULE_LAYOUT_CRC, 'EXPORT_SYMBOL', ''),
    'host_plain': (0x01020304, 'EXPORT_SYMBOL', ''),
    'host_gpl': (0x05060708, 'EXPORT_SYMBOL_GPL', ''),
    'host_ns': (0x090A0B0C, 'EXPORT_SYMBOL_GPL', 'TEST_NS'),
    'nf_nat_ipv4_register_fn': (0xD1744474, 'EXPORT_SYMBOL_GPL', ''),
    'nf_nat_ipv4_unregister_fn': (0x60B00C8B, 'EXPORT_SYMBOL_GPL', ''),
    'nf_nat_ipv6_register_fn': (0x95D7E7AF, 'EXPORT_SYMBOL_GPL', ''),
    'nf_nat_ipv6_unregister_fn': (0x4DA3A6AE, 'EXPORT_SYMBOL_GPL', ''),
}


def align(value, alignment=8):
    return (value + alignment - 1) & -alignment


def make_module(name, imports=None, exports=None, weak_imports=None,
                versions=None, license_name='GPL', namespaces=('TEST_NS',),
                depends=(), vermagic=VERMAGIC, machine=183,
                this_module_size=1088, kcfi=None, btf=None):
    """Assemble real ARM64 relocations; do not emulate the verifier's parser."""
    imports, exports = dict(imports or {}), dict(exports or {})
    weak_imports, kcfi = dict(weak_imports or {}), dict(kcfi or {})
    if versions is None:
        versions = dict(imports, **weak_imports, module_layout=MODULE_LAYOUT_CRC)
    lines = ['.text']
    for symbol in exports:
        lines += [f'.global {symbol}', f'.type {symbol}, %function',
                  f'{symbol}:', 'ret', f'.size {symbol}, .-{symbol}']
    for symbol in imports.keys() | weak_imports.keys():
        lines += [f'.weak {symbol}' if symbol in weak_imports else f'.global {symbol}',
                  '.section .data,"aw"', f'.quad {symbol}']
    for suffix, typeid in kcfi.items():
        lines += [f'.weak __kcfi_typeid_{suffix}', f'.set __kcfi_typeid_{suffix}, {typeid}']
    for symbol, (crc, gpl, namespace) in exports.items():
        suffix = '_gpl' if gpl else ''
        lines += [f'.section __ksymtab{suffix},"a"', '.balign 4',
                  f'__ksymtab_{symbol}:', f'.long {symbol} - .',
                  f'.long __kstrtab_{symbol} - .', f'.long __kstrtabns_{symbol} - .',
                  f'.section __kcrctab{suffix},"a"', '.balign 4',
                  f'__crc_{symbol}:', f'.long {crc}',
                  '.section __ksymtab_strings,"a"', f'__kstrtab_{symbol}:',
                  f'.asciz {json.dumps(symbol)}', f'__kstrtabns_{symbol}:',
                  f'.asciz {json.dumps(namespace)}']
    lines += ['.section .modinfo,"a"']
    for key, value in (('name', name), ('license', license_name),
                       ('vermagic', vermagic), ('depends', ','.join(depends))):
        lines.append(f'.asciz {json.dumps(key + "=" + value)}')
    lines += [f'.asciz {json.dumps("import_ns=" + ns)}' for ns in namespaces]
    lines += ['.section __versions,"a"', '.balign 8']
    for symbol, crc in versions.items():
        lines += [f'.quad {crc}', f'.asciz {json.dumps(symbol)}', f'.zero {55 - len(symbol)}']
    lines += ['.section .gnu.linkonce.this_module,"aw"', '.balign 64',
              '.global __this_module', '.type __this_module,%object',
              '__this_module:', f'.zero {this_module_size}',
              '.size __this_module, .-__this_module']
    if btf is not None:
        lines += ['.section .BTF,"a"', '.byte ' + ','.join(map(str, btf))]
    with tempfile.TemporaryDirectory() as tmp:
        obj = Path(tmp) / 'fixture.o'
        subprocess.run([str(ROOT / 'work/toolchain/bin/clang'), '--target=aarch64-linux-gnu',
                        '-c', '-x', 'assembler', '-o', str(obj), '-'],
                       input='\n'.join(lines) + '\n', text=True, check=True, capture_output=True)
        image = bytearray(obj.read_bytes())
    struct.pack_into('<H', image, 18, machine)
    return bytes(image)


def symvers_rows(exports, provider='vmlinux'):
    return ''.join(f'0x{crc:08x}\t{name}\t{provider}\t{license_name}\t{namespace}\n'
                   for name, (crc, license_name, namespace) in sorted(exports.items()))


class ModuleSetFixture:
    def __init__(self, root):
        self.root = Path(root)
        self.output = self.root / 'output/abi-port'
        self.output.mkdir(parents=True)
        (self.root / 'reports').mkdir()
        self.host_path = self.root / 'Module.symvers'
        self.host_path.write_text(symvers_rows(HOST))
        self.generated = self.root / 'reports/abi-port-built-module-exports.symvers'
        self.modules_dep = self.output / 'modules.dep'
        self.expected = ('nf_tables', 'nft_ct')
        self.make_default()

    def make_default(self):
        core_exports = {'nft_api': (0x11223344, True, '')}
        self.write_module('nf_tables', imports={key: HOST[key][0] for key in ('host_plain', 'host_gpl', 'host_ns')},
                          exports=core_exports, kcfi={'host_plain': 0x10203040, 'nft_api': 0xA0B0C0D0})
        self.write_module('nft_ct', imports={'nft_api': 0x11223344}, depends=('nf_tables',),
                          kcfi={'nft_api': 0xA0B0C0D0})
        self.generated.write_text(symvers_rows({'nft_api': (0x11223344, 'EXPORT_SYMBOL_GPL', '')},
                                               provider='/same/build/nf_tables'))
        self.modules_dep.write_text('abi-port/nf_tables.ko:\n'
                                    'abi-port/nft_ct.ko: abi-port/nf_tables.ko\n')

    def write_module(self, name, **kwargs):
        kwargs.setdefault('namespaces', ('TEST_NS',) if name == 'nf_tables' else ())
        (self.output / f'{name}.ko').write_bytes(make_module(name, **kwargs))

    def verify(self):
        return v.verify_module_set(self.output, self.host_path, self.generated,
                                   self.modules_dep, self.expected)


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = ModuleSetFixture(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def assertFailure(self, result, text):
        self.assertEqual(result['objective_static'], 'fail', result['failures'])
        self.assertIn(text, '\n'.join(result['failures']))

    def test_valid_real_elf_exports_and_weak_imports(self):
        raw = make_module('sample', imports={'host_plain': HOST['host_plain'][0]},
                          weak_imports={'optional_missing': 1},
                          exports={'new_symbol': (0x12345678, True, 'NS')})
        path = self.fixture.output / 'sample.ko'
        path.write_bytes(raw)
        elf = v.read_elf(path)
        self.assertEqual(elf.strong_undefined, {'host_plain'})
        self.assertEqual(elf.weak_undefined, {'optional_missing'})
        self.assertEqual(elf.exports['new_symbol']['crc'], 0x12345678)
        self.assertEqual(elf.exports['new_symbol']['namespace'], 'NS')
        self.assertTrue(elf.exports['new_symbol']['gpl_only'])
        self.assertEqual(elf.modinfo['vermagic'], VERMAGIC)

    def test_wrong_machine_and_short_version_record_rejected(self):
        path = self.fixture.output / 'bad.ko'
        path.write_bytes(make_module('bad', machine=62))
        with self.assertRaisesRegex(v.VerificationError, 'AArch64'):
            v.read_elf(path)
        with self.assertRaisesRegex(v.VerificationError, 'multiple of 64'):
            v.parse_version_records(b'\0' * 63, 'fixture')
        with self.assertRaisesRegex(v.VerificationError, 'nonempty'):
            v.parse_version_records(b'', 'fixture')
        with self.assertRaisesRegex(v.VerificationError, 'NUL'):
            v.parse_version_records(struct.pack('<Q', 1) + b'x' * 56, 'fixture')

    def test_module_set_positive_has_explicit_unverified_not_fake_pass(self):
        result = self.fixture.verify()
        self.assertEqual(result['objective_static'], 'pass', result['failures'])
        self.assertEqual(result['dependencies']['nft_ct'], ['nf_tables'])
        self.assertTrue(any('module BTF' in item for item in result['unverified']))
        self.assertTrue(any('host KCFI' in item for item in result['unverified']))
        self.assertTrue(any('nft_api' in item for item in result['unverified']))

    def test_unknown_provider_and_crc_mismatch_fail(self):
        self.fixture.write_module('nft_ct', imports={'ghost': 1}, depends=('nf_tables',))
        self.assertFailure(self.fixture.verify(), 'no original or same-build provider')
        self.fixture.make_default()
        self.fixture.write_module('nft_ct', imports={'nft_api': 0x11223344},
                                  versions={'nft_api': 0xDEADBEEF, 'module_layout': MODULE_LAYOUT_CRC},
                                  depends=('nf_tables',), kcfi={'nft_api': 0xA0B0C0D0})
        self.assertFailure(self.fixture.verify(), 'CRC mismatch')

    def test_missing_version_and_module_layout_fail(self):
        self.fixture.write_module('nft_ct', imports={'nft_api': 0x11223344},
                                  versions={'module_layout': MODULE_LAYOUT_CRC}, depends=('nf_tables',))
        self.assertFailure(self.fixture.verify(), 'missing __versions record')
        self.fixture.make_default()
        self.fixture.write_module('nft_ct', imports={'nft_api': 0x11223344},
                                  versions={'nft_api': 0x11223344}, depends=('nf_tables',))
        self.assertFailure(self.fixture.verify(), 'module_layout')

    def test_gpl_and_namespace_violations_fail(self):
        self.fixture.write_module('nf_tables', imports={'host_gpl': HOST['host_gpl'][0]},
                                  exports={'nft_api': (0x11223344, True, '')}, license_name='Proprietary')
        self.assertFailure(self.fixture.verify(), 'GPL-only')
        self.fixture.make_default()
        core = make_module('nf_tables', imports={'host_ns': HOST['host_ns'][0]}, namespaces=())
        (self.fixture.output / 'nf_tables.ko').write_bytes(core)
        self.assertFailure(self.fixture.verify(), 'namespace TEST_NS')

    def test_missing_inet_nat_names_fail_even_with_fake_versions(self):
        self.fixture.write_module('nft_ct', imports={'nf_nat_inet_register_fn': 0x12345678},
                                  depends=('nf_tables',))
        self.assertFailure(self.fixture.verify(), 'forbidden missing-host NAT import')

    def test_generated_exports_must_match_real_elf(self):
        self.fixture.generated.write_text(symvers_rows({'nft_api': (0x99999999, 'EXPORT_SYMBOL_GPL', '')},
                                               provider='/same/build/nf_tables'))
        self.assertFailure(self.fixture.verify(), 'generated Module.symvers disagrees')

    def test_modinfo_and_modules_dep_must_match_provider_graph(self):
        self.fixture.write_module('nft_ct', imports={'nft_api': 0x11223344}, depends=(),
                                  kcfi={'nft_api': 0xA0B0C0D0})
        self.assertFailure(self.fixture.verify(), '.modinfo depends')
        self.fixture.make_default()
        self.fixture.modules_dep.write_text('abi-port/nf_tables.ko:\nabi-port/nft_ct.ko:\n')
        self.assertFailure(self.fixture.verify(), 'modules.dep dependency mismatch')

    def test_vermagic_this_module_and_inventory_fail(self):
        self.fixture.write_module('nft_ct', imports={'nft_api': 0x11223344}, vermagic='wrong',
                                  depends=('nf_tables',), kcfi={'nft_api': 0xA0B0C0D0})
        self.assertFailure(self.fixture.verify(), 'vermagic')
        self.fixture.make_default()
        self.fixture.write_module('nft_ct', imports={'nft_api': 0x11223344}, this_module_size=1072,
                                  depends=('nf_tables',), kcfi={'nft_api': 0xA0B0C0D0})
        self.assertFailure(self.fixture.verify(), '1088')
        self.fixture.make_default()
        (self.fixture.output / 'unexpected.ko').write_bytes(make_module('unexpected'))
        self.assertFailure(self.fixture.verify(), 'unexpected modules')

    def test_kcfi_internal_disagreement_fails_without_inventing_host_ids(self):
        self.fixture.write_module('nft_ct', imports={'nft_api': 0x11223344}, depends=('nf_tables',),
                                  kcfi={'nft_api': 0xDEADBEEF})
        result = self.fixture.verify()
        self.assertFailure(result, 'KCFI typeid mismatch')
        self.assertTrue(any('host KCFI' in item for item in result['unverified']))

    def test_host_image_kcfi_typeword_mismatch_is_rejected(self):
        image = b'\0' * 4 + struct.pack('<I', 0x12345678) + b'\0' * 4
        self.assertEqual(v.compare_image_kcfi(image, 0x1000, 0x1008, 0x12345678)['observed'], '0x12345678')
        with self.assertRaisesRegex(v.VerificationError, 'KCFI typeid mismatch'):
            v.compare_image_kcfi(image, 0x1000, 0x1008, 0x87654321)
        with self.assertRaisesRegex(v.VerificationError, 'outside Image'):
            v.compare_image_kcfi(image, 0x1000, 0x1000, 1)

    def test_layout_rejects_nft_insertion_and_shifted_named_offsets(self):
        target = """[1] STRUCT 'net' size=4096 vlen=3
\t'wext_nlevents' type_id=1 bits_offset=22080
\t'gen' type_id=1 bits_offset=22272
\t'bpf' type_id=1 bits_offset=22336
"""
        probe = """[1] STRUCT 'net' size=4096 vlen=4
\t'nft' type_id=1 bits_offset=22080
\t'wext_nlevents' type_id=1 bits_offset=22208
\t'gen' type_id=1 bits_offset=22400
\t'bpf' type_id=1 bits_offset=22464
"""
        result = v.compare_btf_layouts(target, probe, ('net',))
        self.assertEqual(result['net']['status'], 'fail')
        self.assertIn('nft', result['net']['unexpected_members'])
        self.assertEqual(result['net']['offset_mismatches']['gen']['built'], 2800)
        self.assertEqual(result['net']['offset_mismatches']['bpf']['target'], 2792)

    def test_layout_compares_bit_offsets_and_widths(self):
        target = "[1] STRUCT 'nf_hook_ops' size=40 vlen=1\n\t'hook_ops_type' type_id=2 bits_offset=200 bitfield_size=8\n"
        shifted = target.replace('bits_offset=200', 'bits_offset=201')
        self.assertEqual(v.compare_btf_layouts(target, target, ('nf_hook_ops',))['nf_hook_ops']['status'], 'pass')
        self.assertEqual(v.compare_btf_layouts(target, shifted, ('nf_hook_ops',))['nf_hook_ops']['status'], 'fail')


    def test_tools_are_required_not_informational_skips(self):
        old_path = os.environ['PATH']
        try:
            os.environ['PATH'] = self.temp.name
            with self.assertRaisesRegex(v.VerificationError, 'required tool'):
                v.require_tools()
        finally:
            os.environ['PATH'] = old_path

    def test_input_hash_mismatch_is_objective_failure(self):
        root = self.fixture.root
        (root / 'inputs/boot-image').mkdir(parents=True)
        (root / 'work/build-abi-port/include/config').mkdir(parents=True)
        (root / 'work/layout-abi-port').mkdir(parents=True)
        original = b'config\n'
        host = b'host\n'
        (root / 'inputs/target.config').write_bytes(original)
        (root / 'inputs/Module.symvers').write_bytes(host)
        (root / 'inputs/boot-image/target.config').write_bytes(original + b'changed')
        (root / 'inputs/boot-image/Module.symvers').write_bytes(host)
        (root / 'inputs/boot-image/target.btf').write_bytes(b'btf')
        (root / 'boot.img').write_bytes(b'boot')
        manifest = {
            'inputs': {'target.config': hashlib.sha256(original).hexdigest(),
                       'Module.symvers': hashlib.sha256(host).hexdigest()},
            'target_release': 'release', 'expected_vermagic': VERMAGIC,
            'toolchain': {'clang_sha256': 'unused'},
        }
        (root / 'inputs/manifest.json').write_text(json.dumps(manifest))
        expectations = v.Expectations(boot_sha256=hashlib.sha256(b'boot').hexdigest(),
                                      btf_sha256=hashlib.sha256(b'btf').hexdigest(), modules=())
        result = v.verify_inputs(root, manifest, expectations)
        self.assertTrue(any('byte-identical' in item for item in result['failures']))


class FullTreeTests(unittest.TestCase):
    def test_verify_shell_returns_nonzero_and_writes_failure_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'inputs').mkdir()
            (root / 'inputs/manifest.json').write_text('{}')
            env = dict(os.environ, PATH='/usr/bin:/bin')
            proc = subprocess.run(['sh', str(ROOT / 'scripts/verify.sh'), '--root', str(root)],
                                  text=True, capture_output=True, env=env, check=False)
            self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            report = json.loads((root / 'reports/abi-port-verification.json').read_text())
            self.assertEqual(report['objective_static'], 'fail')




if __name__ == '__main__':
    unittest.main()
