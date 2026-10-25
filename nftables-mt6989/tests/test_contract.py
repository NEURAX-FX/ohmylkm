"""Breaks caught: accepting changed input bytes, ABI-option drift or CT drift."""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).resolve().parents[1] / 'scripts' / 'buildlib.py'
SPEC = importlib.util.spec_from_file_location('buildlib', PATH) if PATH.exists() else None
LIB = importlib.util.module_from_spec(SPEC) if SPEC else None
if LIB:
    SPEC.loader.exec_module(LIB)

class ContractTests(unittest.TestCase):
    def need(self):
        self.assertIsNotNone(LIB, 'immutable input/config validator is not implemented')

    def test_modified_input_rejected(self):
        self.need()
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / 'input'
            p.write_bytes(b'abc')
            LIB.require_hash(p, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
            p.write_bytes(b'abd')
            with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
                LIB.require_hash(p, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_conntrack_flags_cannot_change(self):
        self.need()
        original = {'CONFIG_NF_CONNTRACK_LABELS': 'n', 'CONFIG_NF_NAT': 'y'}
        with self.assertRaisesRegex(ValueError, 'CONFIG_NF_CONNTRACK_LABELS'):
            LIB.preserve_host_config(original, dict(original, CONFIG_NF_CONNTRACK_LABELS='y'))
        LIB.preserve_host_config(original, dict(original, CONFIG_NF_TABLES='m'))

    def test_disabled_config_parsed(self):
        self.need()
        self.assertEqual(LIB.parse_config('# CONFIG_NF_TABLES is not set\nCONFIG_NF_NAT=y\n'), {'CONFIG_NF_TABLES':'n', 'CONFIG_NF_NAT':'y'})

class ResourceLimitTests(unittest.TestCase):
    def test_kbuild_parallelism_defaults_to_two_and_never_exceeds_it(self):
        self.assertIsNotNone(LIB, 'bounded make command is not implemented')
        with mock.patch.dict('os.environ', {}, clear=True):
            self.assertIn('-j2', LIB.make_command(pathlib.Path('/tmp/build')))
        with mock.patch.dict('os.environ', {'JOBS': '1'}, clear=True):
            self.assertIn('-j1', LIB.make_command(pathlib.Path('/tmp/build')))
        for jobs in ('0', '3', '8', 'invalid'):
            with self.subTest(jobs=jobs), mock.patch.dict('os.environ', {'JOBS': jobs}, clear=True):
                with self.assertRaisesRegex(ValueError, 'JOBS'):
                    LIB.make_command(pathlib.Path('/tmp/build'))

if __name__ == '__main__':
    unittest.main()
