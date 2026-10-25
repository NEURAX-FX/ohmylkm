#!/usr/bin/env python3
"""Fail-closed static verification for the adapted nftables module set.

No device operations, module loading, compilation, or BTF fabrication. Objective
mismatches fail; unavailable runtime/type evidence is reported as unverified.
"""
import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MODULES = (
    'nf_tables', 'nft_ct', 'nft_nat', 'nft_chain_nat', 'nft_masq', 'nft_limit',
    'nft_redir', 'nft_log', 'nft_fib', 'nft_reject', 'nft_fib_ipv4',
    'nft_reject_ipv4', 'nft_fib_ipv6', 'nft_reject_ipv6', 'nft_fib_inet',
    'nft_reject_inet',
)
EXPECTED_VERMAGIC = '6.1.115-android14-oki-xiaoxiaow SMP preempt mod_unload modversions aarch64'
REQUIRED_LAYOUTS = ('net', 'module', 'netns_nf', 'netns_ct', 'nf_conn',
                    'nf_conntrack_net', 'nf_ct_ext', 'nf_hook_state', 'nf_hook_ops')
FORBIDDEN_NAT_IMPORTS = frozenset(('nf_nat_inet_register_fn', 'nf_nat_inet_unregister_fn'))
REQUIRED_ABI_CONFIG = {
    'CONFIG_MODVERSIONS': 'y', 'CONFIG_CFI_CLANG': 'y', 'CONFIG_LTO_NONE': 'y',
    'CONFIG_DEBUG_INFO_BTF': 'y', 'CONFIG_DEBUG_INFO_BTF_MODULES': 'y',
    'CONFIG_MODULE_ALLOW_BTF_MISMATCH': 'y', 'CONFIG_MODULE_SIG_FORCE': 'n',
}
HOST_CONFIG_PREFIXES = ('CONFIG_NF_CONNTRACK', 'CONFIG_NF_CT_', 'CONFIG_NF_NAT',
                        'CONFIG_NF_DEFRAG', 'CONFIG_NETFILTER_NETLINK',
                        'CONFIG_NETFILTER_SYNPROXY', 'CONFIG_NET_ACT_CT', 'CONFIG_NF_FLOW_TABLE')
LICENSES = frozenset(('EXPORT_SYMBOL', 'EXPORT_SYMBOL_GPL'))


class VerificationError(Exception):
    """An input cannot be decoded or a required tool cannot be executed."""


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_json(path):
    try:
        value = json.loads(Path(path).read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f'{path}: cannot read JSON: {error}') from error
    if not isinstance(value, dict):
        raise VerificationError(f'{path}: expected a JSON object')
    return value


def run_tool(arguments):
    executable = shutil.which(arguments[0]) if not Path(arguments[0]).is_absolute() else arguments[0]
    if not executable:
        raise VerificationError(f'required tool unavailable: {arguments[0]}')
    command = [executable, *map(str, arguments[1:])]
    try:
        proc = subprocess.run(command, capture_output=True, check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VerificationError(f'required tool failed: {command[0]}: {error}') from error
    if proc.returncode:
        detail = proc.stderr.decode('utf-8', 'replace').strip()
        raise VerificationError(f'required tool exited {proc.returncode}: {" ".join(command)}: {detail}')
    try:
        return proc.stdout.decode('utf-8')
    except UnicodeDecodeError as error:
        raise VerificationError(f'{command[0]}: output is not UTF-8') from error


def require_tools(clang_path=None):
    for tool in ('llvm-readelf', 'modinfo', 'bpftool'):
        if not shutil.which(tool):
            raise VerificationError(f'required tool unavailable: {tool}')
    clang = clang_path or shutil.which('clang')
    if not clang or not Path(clang).is_file():
        raise VerificationError(f'required tool unavailable: clang ({clang_path or "PATH"})')


def c_string(data, offset, context):
    if not isinstance(offset, int) or offset < 0 or offset >= len(data):
        raise VerificationError(f'{context}: string offset outside section')
    end = data.find(b'\0', offset)
    if end < 0:
        raise VerificationError(f'{context}: unterminated string')
    try:
        return data[offset:end].decode('ascii')
    except UnicodeDecodeError as error:
        raise VerificationError(f'{context}: string is not ASCII') from error


@dataclass
class ModuleELF:
    path: Path
    header: dict
    modinfo: dict
    imports: dict
    versions: dict
    exports: dict
    kcfi: dict
    strong_undefined: set
    weak_undefined: set
    this_module_size: int
    btf_present: bool
    sha256: str


def parse_version_records(data, context):
    if not data:
        raise VerificationError(f'{context}: __versions is empty or missing; nonempty section required')
    if len(data) % 64:
        raise VerificationError(f'{context}: __versions size is not a multiple of 64')
    records = {}
    for offset in range(0, len(data), 64):
        entry = data[offset:offset + 64]
        if entry[4:8] != b'\0\0\0\0':
            raise VerificationError(f'{context}: nonzero upper CRC word at record {offset // 64}')
        raw_name = entry[8:64]
        nul = raw_name.find(b'\0')
        if nul <= 0:
            raise VerificationError(f'{context}: version name lacks a nonempty NUL-terminated name')
        if any(raw_name[nul:]):
            raise VerificationError(f'{context}: nonzero padding in version name at record {offset // 64}')
        try:
            name = raw_name[:nul].decode('ascii')
        except UnicodeDecodeError as error:
            raise VerificationError(f'{context}: version name is not ASCII') from error
        if not re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z0-9_$]+)?', name):
            raise VerificationError(f'{context}: invalid version symbol name {name!r}')
        if name in records:
            raise VerificationError(f'{context}: duplicate __versions record for {name}')
        records[name] = struct.unpack_from('<I', entry)[0]
    return records


def read_elf(path):
    path = Path(path)
    # This invocation is deliberately mandatory even though parsing is local.
    run_tool(['llvm-readelf', '--file-header', str(path)])
    data = path.read_bytes()
    if len(data) < 64:
        raise VerificationError(f'{path}: truncated ELF header')
    fields = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    (ident, elf_type, machine, version, entry, phoff, shoff, flags, ehsize,
     phentsize, phnum, shentsize, shnum, shstrndx) = fields
    if ident[:4] != b'\x7fELF' or ident[4] != 2 or ident[5] != 1 or ident[6] != 1:
        raise VerificationError(f'{path}: expected ELF64 little-endian version-1 header')
    if elf_type != 1:
        raise VerificationError(f'{path}: expected relocatable ET_REL, got {elf_type}')
    if machine != 183:
        raise VerificationError(f'{path}: expected AArch64 EM_AARCH64=183, got {machine}')
    if version != 1 or ehsize != 64 or shentsize != 64 or shnum < 2:
        raise VerificationError(f'{path}: invalid ELF header/version/section table')
    if shstrndx == 0 or shstrndx >= shnum or shoff > len(data) or shnum * 64 > len(data) - shoff:
        raise VerificationError(f'{path}: invalid section table bounds')
    raw_sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + 64 * index)
                    for index in range(shnum)]
    shstr = raw_sections[shstrndx]
    if shstr[9] > len(data) or shstr[5] > len(data) - shstr[4]:
        raise VerificationError(f'{path}: invalid section-name string table')
    shstr_data = data[shstr[4]:shstr[4] + shstr[5]]
    if not shstr_data:
        raise VerificationError(f'{path}: empty section-name string table')
    sections = {}
    for index, row in enumerate(raw_sections):
        name = c_string(shstr_data, row[0], f'{path}: section {index}') if index else ''
        if not name and index:
            raise VerificationError(f'{path}: unnamed section {index}')
        if name in sections:
            raise VerificationError(f'{path}: duplicate section {name}')
        if row[4] > len(data) or row[5] > len(data) - row[4]:
            raise VerificationError(f'{path}: section {name or index} exceeds file bounds')
        sections[name] = {'index': index, 'row': row,
                          'data': data[row[4]:row[4] + row[5]]}
    for required in ('.symtab', '.strtab', '.modinfo', '.gnu.linkonce.this_module', '__versions'):
        if required not in sections:
            raise VerificationError(f'{path}: missing required section {required}')
    symtab = sections['.symtab']['row']
    if symtab[1] != 2 or symtab[9] != 24 or len(sections['.symtab']['data']) % 24:
        raise VerificationError(f'{path}: malformed ELF64 symbol table')
    strtab_name = raw_sections[symtab[6]][0] if symtab[6] < shnum else None
    if symtab[6] >= shnum or strtab_name is None:
        raise VerificationError(f'{path}: invalid symbol string-table link')
    strtab = sections['.strtab']['data']
    symbols = []
    for index, offset in enumerate(range(0, len(sections['.symtab']['data']), 24)):
        name_off, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', sections['.symtab']['data'], offset)
        name = c_string(strtab, name_off, f'{path}: symbol {index}') if name_off else ''
        symbols.append({'name': name, 'bind': info >> 4, 'type': info & 15,
                        'shndx': shndx, 'value': value, 'size': size, 'index': index})
    strong, weak, kcfi = set(), set(), {}
    for symbol in symbols:
        name = symbol['name']
        if symbol['shndx'] == 0 and name:
            if symbol['bind'] == 1:
                strong.add(name)
            elif symbol['bind'] == 2:
                weak.add(name)
            else:
                raise VerificationError(f'{path}: unsupported undefined binding for {name}')
        if name.startswith('__kcfi_typeid_') and symbol['shndx'] != 0:
            if symbol['shndx'] != 0xFFF1 or symbol['bind'] != 2 or symbol['value'] > 0xFFFFFFFF:
                raise VerificationError(f'{path}: malformed KCFI absolute typeid {name}')
            suffix = name[len('__kcfi_typeid_'):]
            if not suffix:
                raise VerificationError(f'{path}: empty KCFI typeid suffix')
            kcfi[suffix] = symbol['value']
    raw_modinfo = sections['.modinfo']['data']
    if not raw_modinfo or raw_modinfo[-1] != 0:
        raise VerificationError(f'{path}: malformed .modinfo termination')
    modinfo = {}
    for item in raw_modinfo[:-1].split(b'\0'):
        try:
            key, value = item.decode('utf-8').split('=', 1)
        except (UnicodeDecodeError, ValueError) as error:
            raise VerificationError(f'{path}: malformed .modinfo entry') from error
        if not key:
            raise VerificationError(f'{path}: empty .modinfo key')
        if key in ('import_ns', 'alias', 'firmware'):
            modinfo.setdefault(key, []).append(value)
        else:
            if key in modinfo:
                raise VerificationError(f'{path}: duplicate .modinfo key {key}')
            modinfo[key] = value
    for key in ('license', 'vermagic', 'name', 'depends'):
        if key not in modinfo:
            raise VerificationError(f'{path}: missing .modinfo {key}')
    external = run_tool(['modinfo', str(path)])
    external_info = {}
    for line in external.splitlines():
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        key, value = key.strip(), value.strip()
        if key in ('import_ns', 'alias', 'firmware'):
            external_info.setdefault(key, []).append(value)
        elif key in external_info:
            raise VerificationError(f'{path}: duplicate modinfo output key {key}')
        else:
            external_info[key] = value
    for key in ('license', 'vermagic', 'name', 'depends', 'import_ns'):
        if modinfo.get(key, [] if key == 'import_ns' else None) != external_info.get(key, [] if key == 'import_ns' else None):
            raise VerificationError(f'{path}: .modinfo {key} disagrees with modinfo tool')
    versions = parse_version_records(sections['__versions']['data'], f'{path}: __versions')
    exports = {}
    by_index = {section['index']: section for section in sections.values()}
    export_sections = {section['index'] for name, section in sections.items()
                       if name in ('__ksymtab', '__ksymtab_gpl')}
    relocations = {}
    for section in sections.values():
        row = section['row']
        if row[1] != 4 or row[7] not in export_sections:
            continue
        if row[6] != sections['.symtab']['index'] or row[9] != 24 or row[5] % 24:
            raise VerificationError(f'{path}: malformed export RELA section')
        for offset in range(0, row[5], 24):
            location, info, addend = struct.unpack_from('<QQq', section['data'], offset)
            symbol_index, kind = info >> 32, info & 0xffffffff
            key = (row[7], location)
            if kind != 261 or symbol_index >= len(symbols) or key in relocations:
                raise VerificationError(f'{path}: invalid or duplicate export PREL32 relocation')
            relocations[key] = (symbols[symbol_index], addend)
    def export_target(section_index, offset):
        relocation = relocations.get((section_index, offset))
        if relocation is None:
            raise VerificationError(f'{path}: export field lacks PREL32 relocation at {offset}')
        symbol, addend = relocation
        if symbol['shndx'] not in by_index or not symbol['shndx']:
            raise VerificationError(f'{path}: export field targets an undefined/non-section symbol')
        return symbol, addend
    def export_string(section_index, offset):
        symbol, addend = export_target(section_index, offset)
        strings = sections.get('__ksymtab_strings')
        if strings is None or symbol['shndx'] != strings['index']:
            raise VerificationError(f'{path}: export string relocation targets the wrong section')
        return c_string(strings['data'], symbol['value'] + addend, f'{path}: export string')
    for table_name, crc_name, gpl in (('__ksymtab', '__kcrctab', False),
                                     ('__ksymtab_gpl', '__kcrctab_gpl', True)):
        table = sections.get(table_name, {}).get('data', b'')
        crcs = sections.get(crc_name, {}).get('data', b'')
        if len(table) % 12 or len(crcs) != len(table) // 12 * 4:
            raise VerificationError(f'{path}: inconsistent {table_name}/{crc_name} sizes')
        if not table:
            continue
        table_index = sections[table_name]['index']
        for offset in range(0, len(table), 12):
            name = export_string(table_index, offset + 4)
            namespace = export_string(table_index, offset + 8)
            definition, addend = export_target(table_index, offset)
            if not name or name in exports or definition['name'] != name or addend:
                raise VerificationError(f'{path}: invalid, duplicate or undefined export {name!r}')
            crc_symbols = [symbol for symbol in symbols if symbol['name'] == '__crc_' + name]
            if len(crc_symbols) != 1:
                raise VerificationError(f'{path}: export {name} lacks a unique CRC symbol')
            crc_symbol = crc_symbols[0]
            location = crc_symbol['value']
            if crc_symbol['shndx'] != sections[crc_name]['index'] or location % 4 or location + 4 > len(crcs):
                raise VerificationError(f'{path}: export {name} has invalid CRC location')
            exports[name] = {'crc': struct.unpack_from('<I', crcs, location)[0],
                             'gpl_only': gpl, 'namespace': namespace}
    this_section = sections['.gnu.linkonce.this_module']
    this_symbols = [s for s in symbols if s['name'] == '__this_module' and s['shndx'] != 0]
    if len(this_symbols) != 1:
        raise VerificationError(f'{path}: expected exactly one defined __this_module symbol')
    this_size = this_symbols[0]['size']
    if this_size != 1088 or this_section['row'][5] != 1088:
        raise VerificationError(f'{path}: struct module/__this_module must be 1088 bytes, got {this_size}/{this_section["row"][5]}')
    btf = sections.get('.BTF', {}).get('data')
    if btf:
        if len(btf) < 24:
            raise VerificationError(f'{path}: truncated .BTF header')
        magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from('<HBBIIIII', btf)
        if magic != 0xEB9F or version != 1 or hdr_len < 24 or hdr_len > len(btf):
            raise VerificationError(f'{path}: malformed .BTF header')
        end = hdr_len + str_off + str_len
        if hdr_len + type_off + type_len > len(btf) or end > len(btf):
            raise VerificationError(f'{path}: .BTF sections exceed section size')
        run_tool(['bpftool', 'btf', 'dump', 'file', str(path), 'format', 'raw'])
    return ModuleELF(path=path,
                     header={'class': 64, 'endianness': 'little', 'type': 'REL', 'machine': 'AArch64'},
                     modinfo=modinfo, imports={}, versions=versions, exports=exports,
                     kcfi=kcfi, strong_undefined=strong, weak_undefined=weak,
                     this_module_size=this_size, btf_present=bool(btf), sha256=sha256(path))


def parse_symvers(path):
    result = {}
    try:
        lines = Path(path).read_text().splitlines()
    except (OSError, UnicodeError) as error:
        raise VerificationError(f'{path}: cannot read Module.symvers: {error}') from error
    if not lines:
        raise VerificationError(f'{path}: Module.symvers is empty')
    for line_number, line in enumerate(lines, 1):
        fields = line.split('\t')
        if len(fields) != 5 or not re.fullmatch(r'0x[0-9a-f]{8}', fields[0]):
            raise VerificationError(f'{path}:{line_number}: malformed five-field Module.symvers row')
        crc, name, provider, license_name, namespace = fields
        if not name or not provider or license_name not in LICENSES or name in result:
            raise VerificationError(f'{path}:{line_number}: duplicate/invalid export {name!r}')
        result[name] = {'crc': int(crc, 16), 'provider': provider,
                        'license': license_name, 'namespace': namespace,
                        'line': line}
    return result


def module_dependencies(path):
    result = {}
    try:
        lines = Path(path).read_text().splitlines()
    except (OSError, UnicodeError) as error:
        raise VerificationError(f'{path}: cannot read modules.dep: {error}') from error
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        if ':' not in line:
            raise VerificationError(f'{path}:{line_number}: malformed modules.dep row')
        module_path, raw_dependencies = line.split(':', 1)
        module = Path(module_path.strip()).name
        if not module.endswith('.ko') or module in result:
            raise VerificationError(f'{path}:{line_number}: duplicate/invalid module {module}')
        dependencies = []
        for item in raw_dependencies.split():
            dependency = Path(item).name
            if not dependency.endswith('.ko'):
                raise VerificationError(f'{path}:{line_number}: invalid dependency {item}')
            if dependency in dependencies:
                raise VerificationError(f'{path}:{line_number}: duplicate dependency {dependency}')
            dependencies.append(dependency)
        result[module] = dependencies
    if not result:
        raise VerificationError(f'{path}: modules.dep is empty')
    return result


def topological_order(expected, graph):
    remaining = {name: set(graph.get(name, ())) for name in expected}
    order = []
    while remaining:
        ready = [name for name in expected if name in remaining and not remaining[name]]
        if not ready:
            raise VerificationError('dependency cycle: ' + ', '.join(sorted(remaining)))
        for name in ready:
            order.append(name)
            del remaining[name]
        for dependencies in remaining.values():
            dependencies.difference_update(ready)
    return order


def verify_module_set(output, host_path, generated_path, dep_path, expected=EXPECTED_MODULES):
    failures, unverified = [], []
    output, host_path, generated_path, dep_path = map(Path, (output, host_path, generated_path, dep_path))
    try:
        host = parse_symvers(host_path)
    except VerificationError as error:
        host = {}
        failures.append(str(error))
    actual_paths = sorted(output.glob('*.ko'))
    actual_names = {path.stem for path in actual_paths}
    missing, unexpected = set(expected) - actual_names, actual_names - set(expected)
    if missing:
        failures.append('missing modules: ' + ', '.join(sorted(missing)))
    if unexpected:
        failures.append('unexpected modules: ' + ', '.join(sorted(unexpected)))
    modules, module_rows, provider_map, kcfi_map = {}, [], {}, {}
    for path in actual_paths:
        if path.stem not in expected:
            continue
        try:
            module = read_elf(path)
        except (OSError, VerificationError) as error:
            failures.append(str(error))
            continue
        modules[path.stem] = module
        depends = module.modinfo['depends'].split(',') if module.modinfo['depends'] else []
        if len(depends) != len(set(depends)):
            failures.append(f'{path.name}: duplicate .modinfo depends entries')
        row = {'sha256': module.sha256, 'license': module.modinfo['license'],
               'vermagic': module.modinfo['vermagic'], 'this_module_size': module.this_module_size,
               'strong_undefined': sorted(module.strong_undefined),
               'weak_undefined': sorted(module.weak_undefined),
               'version_count': len(module.versions), 'exports': module.exports,
               'kcfi_typeids': {name: f'0x{crc:08x}' for name, crc in sorted(module.kcfi.items())},
               'btf_present': module.btf_present, 'depends': depends}
        module_rows.append((path.stem, row))
        if module.modinfo['name'] != path.stem:
            failures.append(f'{path.name}: .modinfo name is {module.modinfo["name"]!r}')
        if module.modinfo['license'] != 'GPL':
            failures.append(f'{path.name}: license must be GPL, got {module.modinfo["license"]!r}')
        if module.modinfo['vermagic'] != EXPECTED_VERMAGIC:
            failures.append(f'{path.name}: vermagic mismatch: {module.modinfo["vermagic"]!r}')
        forbidden = module.strong_undefined & FORBIDDEN_NAT_IMPORTS
        forbidden |= module.versions.keys() & FORBIDDEN_NAT_IMPORTS
        if forbidden:
            failures.append(f'{path.name}: forbidden missing-host NAT import: {", ".join(sorted(forbidden))}')
        expected_versions = module.strong_undefined | {'module_layout'}
        for name in sorted(expected_versions - module.versions.keys()):
            failures.append(f'{path.name}: missing __versions record for {name}')
        for name in sorted(module.versions.keys() - expected_versions):
            failures.append(f'{path.name}: unexpected __versions record for {name}')
        if 'module_layout' in host and module.versions.get('module_layout') != host['module_layout']['crc']:
            failures.append(f'{path.name}: module_layout CRC mismatch')
        if not module.btf_present:
            unverified.append(f'{path.name}: module BTF absent; loader tolerates this, but module type metadata is unverified')
        else:
            unverified.append(f'{path.name}: module BTF parses, but no original vmlinux ELF/base-linked type validation is available')
        for export, details in module.exports.items():
            if export in host:
                failures.append(f'{path.name}: export {export} duplicates original host export')
            if export in provider_map:
                failures.append(f'{path.name}: export {export} also provided by {provider_map[export][0]}')
            else:
                provider_map[export] = (path.stem, details)
        for suffix, typeid in module.kcfi.items():
            kcfi_map.setdefault(suffix, []).append((path.stem, typeid))
    for suffix, values in sorted(kcfi_map.items()):
        if len({value for _, value in values}) != 1:
            failures.append(f'KCFI typeid mismatch for {suffix}: {values}')
        if suffix not in provider_map:
            unverified.append(f'KCFI named type {suffix} is inventoried; host KCFI expectations and complete callback equivalence are not checked by the module-only verifier')
        else:
            unverified.append(f'KCFI typeid for same-build {suffix} is internally compared; target-host prototype equivalence remains unverified')
    try:
        generated = parse_symvers(generated_path)
        actual_generated = {}
        for export, details in generated.items():
            provider = Path(details['provider']).stem
            if provider not in modules:
                failures.append(f'generated Module.symvers {export}: provider {provider} is not an adapted module')
                continue
            actual = modules[provider].exports.get(export)
            expected_row = {'crc': actual['crc'], 'provider': details['provider'],
                            'license': 'EXPORT_SYMBOL_GPL' if actual['gpl_only'] else 'EXPORT_SYMBOL',
                            'namespace': actual['namespace'], 'line': details['line']} if actual else None
            if actual is None or details['crc'] != actual['crc'] or details['license'] != expected_row['license'] or details['namespace'] != actual['namespace']:
                failures.append(f'generated Module.symvers disagrees with real ELF export {provider}:{export}')
                continue
            actual_generated[export] = details
        expected_generated = {export for export, (provider, _) in provider_map.items()}
        for export in sorted(expected_generated - generated.keys()):
            failures.append(f'generated Module.symvers missing real export {export}')
    except VerificationError as error:
        failures.append(str(error))
    dependencies = {}
    for name, module in modules.items():
        imported_namespaces = set(module.modinfo.get('import_ns', []))
        used_providers = set()
        for symbol in sorted(module.strong_undefined):
            if symbol in FORBIDDEN_NAT_IMPORTS:
                continue
            if symbol in host:
                details = host[symbol]
                provider = 'vmlinux'
                gpl_only = details['license'] == 'EXPORT_SYMBOL_GPL'
                namespace = details['namespace']
                expected_crc = details['crc']
            elif symbol in provider_map:
                provider, details = provider_map[symbol]
                gpl_only = details['gpl_only']
                namespace = details['namespace']
                expected_crc = details['crc']
                used_providers.add(provider)
            else:
                failures.append(f'{name}.ko: {symbol} has no original or same-build provider')
                continue
            if module.versions.get(symbol) != expected_crc:
                failures.append(f'{name}.ko: CRC mismatch for {symbol}: {module.versions.get(symbol)} != 0x{expected_crc:08x}')
            if gpl_only and module.modinfo['license'] != 'GPL':
                failures.append(f'{name}.ko: non-GPL consumer uses GPL-only {symbol} from {provider}')
            if namespace and namespace not in imported_namespaces:
                failures.append(f'{name}.ko: {symbol} requires namespace {namespace}, but import_ns is absent')
        metadata_dependencies = set(module.modinfo['depends'].split(',')) - {''}
        if metadata_dependencies != used_providers:
            failures.append(f'{name}.ko: .modinfo depends {sorted(metadata_dependencies)} does not match providers {sorted(used_providers)}')
        dependencies[name] = sorted(used_providers)
    try:
        dep_rows = module_dependencies(dep_path)
        normalized = {Path(name).stem: [Path(item).stem for item in values]
                      for name, values in dep_rows.items()}
        for name in expected:
            expected_edges = dependencies.get(name)
            if expected_edges is None:
                continue
            if name not in normalized:
                failures.append(f'modules.dep missing {name}.ko')
            elif set(normalized[name]) != set(expected_edges):
                failures.append(f'modules.dep dependency mismatch for {name}.ko: {normalized[name]} != {expected_edges}')
        for name in sorted(normalized.keys() - expected):
            failures.append(f'modules.dep has unexpected module {name}')
    except VerificationError as error:
        failures.append(str(error))
    try:
        load_order = topological_order(expected, dependencies)
    except VerificationError as error:
        failures.append(str(error))
        load_order = []
    return {'objective_static': 'fail' if failures else 'pass',
            'failures': failures, 'unverified': unverified,
            'modules': [dict(module=name, **row) for name, row in sorted(module_rows)],
            'dependencies': dependencies, 'load_order': load_order}


def parse_btf_layouts(text):
    layouts, current = {}, None
    for line in text.splitlines():
        header = re.match(r"^\[(\d+)\] STRUCT '([^']+)' size=(\d+) vlen=(\d+)", line)
        if header:
            name = header[2]
            current = None
            if name in REQUIRED_LAYOUTS:
                current = {'type_id': int(header[1]), 'size': int(header[3]),
                           'vlen': int(header[4]), 'parsed_members': 0, 'members': {},
                           'member_bits': {}, 'bitfields': {}, 'errors': []}
                layouts.setdefault(name, []).append(current)
            continue
        if line.startswith('['):
            current = None
        if current is None or not line.strip():
            continue
        member = re.fullmatch(r"\s*'([^']+)' type_id=\d+ bits_offset=(\d+)(?: bitfield_size=(\d+))?", line)
        if not member:
            current['errors'].append('unrecognized member: ' + line.strip())
            continue
        current['parsed_members'] += 1
        name, bits = member[1], int(member[2])
        if name == '(anon)':
            continue
        if name in current['members']:
            current['errors'].append('duplicate member: ' + name)
        current['members'][name] = bits // 8
        current['member_bits'][name] = bits
        if member[3]:
            current['bitfields'][name] = int(member[3])
    for records in layouts.values():
        for record in records:
            if record['parsed_members'] != record['vlen']:
                record['errors'].append('incomplete member list')
    return layouts


def compare_btf_layouts(target_text, built_text, required=REQUIRED_LAYOUTS):
    target, built = parse_btf_layouts(target_text), parse_btf_layouts(built_text)
    result = {}
    for name in required:
        records, probes = target.get(name, []), built.get(name, [])
        actual = probes[0] if probes else None
        entry = {'target': records, 'built': actual, 'offset_mismatches': {},
                 'missing_members': [], 'unexpected_members': [], 'errors': []}
        if not records or actual is None:
            entry['errors'].append('target or probe has no complete record')
        elif records:
            reference = records[0]
            entry['missing_members'] = sorted(reference['members'].keys() - actual['members'].keys())
            entry['unexpected_members'] = sorted(actual['members'].keys() - reference['members'].keys())
            for member in reference['members'].keys() & actual['members'].keys():
                if reference['member_bits'][member] != actual['member_bits'][member]:
                    entry['offset_mismatches'][member] = {'target': reference['members'][member],
                        'built': actual['members'][member], 'target_bits': reference['member_bits'][member],
                        'built_bits': actual['member_bits'][member]}
            for record in records + probes:
                entry['errors'].extend(record['errors'])
                if any(record[key] != reference[key] for key in ('size', 'member_bits', 'bitfields')):
                    entry['errors'].append(f'layout differs at type ID {record["type_id"]}')
        entry['status'] = 'fail' if (entry['errors'] or entry['missing_members'] or
                                    entry['unexpected_members'] or entry['offset_mismatches']) else 'pass'
        result[name] = entry
    return result


def probe_btf_text(root, probe):
    """Convert only the probe's DWARF to detached BTF, never module metadata."""
    pahole = root / 'work/host/usr/bin/pahole'
    if not pahole.is_file():
        raise VerificationError(f'required tool unavailable: {pahole}')
    environment = os.environ.copy()
    environment['LD_LIBRARY_PATH'] = str(root / 'work/host/usr/lib64') + ':' + environment.get('LD_LIBRARY_PATH', '')
    with tempfile.TemporaryDirectory(prefix='nft-layout-') as tmp:
        detached = Path(tmp) / 'probe.btf'
        proc = subprocess.run([str(pahole), '-j1', '--btf_encode_detached=' + str(detached), str(probe)],
                              env=environment, capture_output=True, timeout=60)
        if proc.returncode or not detached.is_file():
            raise VerificationError(f'probe DWARF conversion failed: {proc.stderr.decode("utf-8", "replace")}')
        return run_tool(['bpftool', 'btf', 'dump', 'file', str(detached), 'format', 'raw'])


@dataclass
class Expectations:
    boot_sha256: str
    btf_sha256: str
    clang_path: object = None
    boot_path: object = None
    modules: tuple = EXPECTED_MODULES
    extra_input_hashes: dict = field(default_factory=dict)


def default_expectations(root):
    evidence = load_json(Path(root) / 'reports/boot-image-evidence.json')
    return Expectations(boot_sha256=evidence['source_boot_image']['sha256'],
                        btf_sha256=evidence['btf']['sha256'],
                        clang_path=Path(root) / 'work/toolchain/bin/clang',
                        boot_path=Path(root).parent / evidence['source_boot_image']['path'])


def parse_config(text):
    result = {}
    for line in text.splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1)
            result[key] = value
        elif re.fullmatch(r'# CONFIG_\w+ is not set', line):
            result[line.split()[1]] = 'n'
    return result


def read_text(path):
    try:
        return Path(path).read_text()
    except (OSError, UnicodeError) as error:
        raise VerificationError(f'{path}: cannot read text: {error}') from error


def hash_check(path, expected, label, failures):
    try:
        actual = sha256(path)
    except OSError as error:
        failures.append(f'{label}: cannot hash {path}: {error}')
        return None
    if actual != expected:
        failures.append(f'{label}: SHA256 mismatch {actual} != {expected}')
    return actual


def verify_inputs(root, manifest, expectations):
    root = Path(root)
    failures, hashes = [], {}
    for name, expected in manifest.get('inputs', {}).items():
        digest = hash_check(root / 'inputs' / name, expected, f'input {name}', failures)
        if digest:
            hashes[f'inputs/{name}'] = digest
    boot_digest = hash_check(Path(expectations.boot_path or root / 'boot.img'), expectations.boot_sha256, 'boot.img', failures)
    if boot_digest:
        hashes['boot.img'] = boot_digest
    for name, recovered in (('target.config', 'target.config'), ('Module.symvers', 'Module.symvers')):
        original, image = root / 'inputs' / name, root / 'inputs/boot-image' / recovered
        try:
            if original.read_bytes() != image.read_bytes():
                failures.append(f'image-recovered {recovered} is not byte-identical to original input {name}')
            hashes[f'inputs/boot-image/{recovered}'] = sha256(image)
        except OSError as error:
            failures.append(f'cannot compare recovered {recovered}: {error}')
    btf_digest = hash_check(root / 'inputs/boot-image/target.btf', expectations.btf_sha256,
                            'target BTF', failures)
    if btf_digest:
        hashes['inputs/boot-image/target.btf'] = btf_digest
    for relative, expected in expectations.extra_input_hashes.items():
        digest = hash_check(root / relative, expected, relative, failures)
        if digest:
            hashes[relative] = digest
    return {'objective_static': 'fail' if failures else 'pass', 'failures': failures,
            'hashes': hashes, 'source': 'supplied boot.img, not identification of a running device'}


def compare_image_kcfi(image, text_base, address, expected):
    offset = address - text_base
    if offset < 4 or offset > len(image) - 4:
        raise VerificationError('KCFI function address is outside Image')
    observed = struct.unpack_from('<I', image, offset - 4)[0]
    if observed != expected:
        raise VerificationError(f'KCFI typeid mismatch: expected 0x{expected:08x}, Image 0x{observed:08x}')
    return {'address': f'0x{address:x}', 'image_offset': offset,
            'expected': f'0x{expected:08x}', 'observed': f'0x{observed:08x}'}


def verify_host_kcfi(root, modules):
    image = (root / 'inputs/boot-image/Image').read_bytes()
    symbols = {}
    for line in read_text(root / 'inputs/boot-image/target.kallsyms').splitlines():
        fields = line.split()
        if len(fields) >= 3:
            symbols[fields[2]] = int(fields[0], 16)
    if '_text' not in symbols:
        raise VerificationError('Image kallsyms has no _text mapping')
    host = parse_symvers(root / 'inputs/Module.symvers')
    checks, failures, unverified = [], [], []
    for module in modules:
        for name, expected in module['kcfi_typeids'].items():
            if name not in module['strong_undefined'] or name not in host:
                continue
            if name not in symbols:
                unverified.append(f'host KCFI: no Image address for {name}')
                continue
            try:
                check = compare_image_kcfi(image, symbols['_text'], symbols[name], int(expected, 16))
                checks.append(dict(module=module['module'], function=name, **check))
            except VerificationError as error:
                failures.append(f'{module["module"]}.ko: {name}: {error}')
    return {'checks': checks, 'failures': failures, 'unverified': unverified}


def verify_tree(root, expectations):
    root = Path(root)
    failures, unverified = [], []
    manifest = load_json(root / 'inputs/manifest.json')
    if manifest.get('expected_vermagic') != EXPECTED_VERMAGIC:
        failures.append('manifest expected_vermagic differs from strict verifier requirement')
    inputs = verify_inputs(root, manifest, expectations)
    failures.extend(inputs['failures'])
    clang_path = Path(expectations.clang_path or root / 'work/toolchain/bin/clang')
    expected_clang = manifest.get('toolchain', {}).get('clang_sha256')
    if expected_clang:
        hash_check(clang_path, expected_clang, 'Clang compiler', failures)
    require_tools(clang_path)
    out = root / 'work/build-abi-port'
    try:
        release = read_text(out / 'include/config/kernel.release').strip()
        if release != manifest.get('target_release'):
            failures.append(f'build kernel.release mismatch: {release!r}')
    except VerificationError as error:
        failures.append(str(error))
    try:
        if (out / 'Module.symvers').read_bytes() != (root / 'inputs/Module.symvers').read_bytes():
            failures.append('build Module.symvers differs from original host table')
    except OSError as error:
        failures.append(f'cannot compare build Module.symvers: {error}')
    try:
        original = parse_config(read_text(root / 'inputs/target.config'))
        current = parse_config(read_text(out / '.config'))
        for key, expected in REQUIRED_ABI_CONFIG.items():
            if current.get(key, 'n') != expected:
                failures.append(f'build config {key}: {current.get(key, "n")} != {expected}')
        if current.get('CONFIG_NF_TABLES') != 'm':
            failures.append('build config CONFIG_NF_TABLES must be m')
        for key in original.keys() | current.keys():
            if key.startswith(HOST_CONFIG_PREFIXES) and original.get(key, 'n') != current.get(key, 'n'):
                failures.append(f'host configuration drift: {key}: {original.get(key, "n")} -> {current.get(key, "n")}')
    except VerificationError as error:
        failures.append(str(error))
    results_path = root / 'reports/abi-port-build-results.json'
    try:
        results = json.loads(read_text(results_path))
        expected_results = [{'module': name + '.ko'} for name in expectations.modules]
        normalized = sorted((row.get('module'), row.get('exit_code')) for row in results)
        if normalized != sorted((row['module'], 0) for row in expected_results):
            failures.append('build results do not show exactly all expected modules exiting 0')
    except (VerificationError, ValueError, TypeError, AttributeError) as error:
        failures.append(f'invalid build results: {error}')
    modules = verify_module_set(root / 'output/abi-port', root / 'inputs/Module.symvers',
                                root / 'reports/abi-port-built-module-exports.symvers',
                                root / 'output/abi-port/modules.dep', expectations.modules)
    failures.extend(modules['failures'])
    unverified.extend(modules['unverified'])
    bindings = {}
    try:
        artifact_hashes = load_json(root / 'reports/abi-port-artifact-sha256.json')
        if set(artifact_hashes) != {name + '.ko' for name in expectations.modules}:
            failures.append('build artifact hash manifest has incomplete or unexpected modules')
        for module in modules['modules']:
            if artifact_hashes.get(module['module'] + '.ko') != module['sha256']:
                failures.append(f'{module["module"]}.ko: artifact differs from the recorded build SHA256')
        bindings = load_json(root / 'reports/abi-port-layout-inputs.json')
        required_bindings = {'work/layout-abi-port/probe.o', 'work/layout-abi-port/probe.c',
            'work/build-abi-port/.config', 'reports/abi-port-built-module-exports.symvers',
            'work/kernel-abi-port/include/net/net_namespace.h',
            'work/kernel-abi-port/include/net/netfilter/nf_tables.h',
            'work/kernel-abi-port/net/netfilter/nf_tables_api.c',
            'work/kernel-abi-port/net/netfilter/nf_tables_core.c',
            'work/kernel-abi-port/net/netfilter/nft_chain_nat.c'}
        if set(bindings) != required_bindings:
            failures.append('probe/config/source binding manifest is incomplete or unexpected')
        for relative in required_bindings & bindings.keys():
            hash_check(root / relative, bindings[relative], 'build binding ' + relative, failures)
    except VerificationError as error:
        failures.append(str(error))
    host_kcfi = {'checks': [], 'failures': [], 'unverified': []}
    try:
        host_kcfi = verify_host_kcfi(root, modules['modules'])
        failures.extend(host_kcfi['failures'])
        checked_names = {check['function'] for check in host_kcfi['checks']}
        unverified = [item for item in unverified if not any(
            item.startswith('KCFI named type ' + name + ' ') for name in checked_names)]
        unverified.extend(host_kcfi['unverified'])
    except (OSError, ValueError, VerificationError) as error:
        failures.append(f'host KCFI verification failed closed: {error}')
    layout = {}
    probe = root / 'work/layout-abi-port/probe.o'
    try:
        btf_text = run_tool(['bpftool', 'btf', 'dump', 'file', str(root / 'inputs/boot-image/target.btf'), 'format', 'raw'])
        if not probe.is_file():
            raise VerificationError(f'{probe}: required adapted layout probe is absent')
        probe_text = probe_btf_text(root, probe)
        layout = compare_btf_layouts(btf_text, probe_text, REQUIRED_LAYOUTS)
        for name, result in layout.items():
            if result['status'] != 'pass':
                failures.append(f'layout {name}: target/probe mismatch: {json.dumps(result, sort_keys=True)}')
    except (OSError, UnicodeError, VerificationError) as error:
        failures.append(f'layout verification failed closed: {error}')
    report = {
        'schema_version': 1,
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'objective_static': 'fail' if failures else 'pass',
        'failures': failures,
        'unverified': sorted(set(unverified + [
            'No module was loaded; runtime behavior, rulesets, network-namespace isolation, and NAT semantics are unverified.',
            'Named host KCFI typewords and same-build IDs do not establish all indirect callback boundaries or nested type compatibility.',
        ])),
        'inputs': inputs,
        'module_set': modules,
        'modules': modules['modules'],
        'dependencies': modules['dependencies'],
        'load_order': modules['load_order'],
        'layout': layout,
        'host_kcfi': host_kcfi,
        'build_bindings': bindings,
        'runtime_verified': False,
        'scope': 'Objective static compatibility checks only. Unverified limitations are not passes and are not static rejection reasons.',
    }
    write_reports(root, report)
    return report


def markdown_report(report):
    lines = [
        '# ABI-port static verification', '',
        f'Objective static result: **{report["objective_static"].upper()}**', '',
        'This result covers only the observed artifacts and supplied boot image. It is not runtime approval.',
        'UNVERIFIED limitations remain listed below; they are neither passes nor objective static mismatches.', '',
        '## Objective failures', '',
    ]
    failures = report.get('failures', [])
    lines += [f'- {item}' for item in failures] or ['- None.']
    modules = report.get('modules', [])
    lines += ['', '## Observed module inventory', '',
              f'- Modules checked: **{len(modules)}**.',
              f'- Load order: `{", ".join(report.get("load_order", [])) or "unavailable"}`.', '',
              '| Module | SHA256 | Imports | Exports | Versions | struct module | BTF |',
              '|---|---|---:|---:|---:|---:|---|']
    for module in modules:
        lines.append(f'| {module["module"]}.ko | `{module["sha256"]}` | {len(module["strong_undefined"])} | '
                     f'{len(module["exports"])} | {module["version_count"]} | {module["this_module_size"]} | '
                     f'{"present" if module["btf_present"] else "absent / UNVERIFIED metadata"} |')
    layouts = report.get('layout', {})
    lines += ['', '## Target BTF versus Kbuild/DWARF probe', '',
              '| Structure | Result | Target size | Probe size | Missing | Unexpected | Offset mismatches |',
              '|---|---|---:|---:|---:|---:|---:|']
    for name, result in layouts.items():
        target_size = result['target'][0]['size'] if result.get('target') else 'missing'
        built_size = result['built'].get('size') if result.get('built') else 'missing'
        lines.append(f'| {name} | {result["status"].upper()} | {target_size} | {built_size} | '
                     f'{len(result["missing_members"])} | {len(result["unexpected_members"])} | {len(result["offset_mismatches"])} |')
    if not layouts:
        lines.append('| Not decoded | FAIL | — | — | — | — | — |')
    lines += ['', '## Observed host KCFI typewords', '',
              '| Consumer | Function | Module expectation | Image typeword |',
              '|---|---|---|---|']
    for check in report.get('host_kcfi', {}).get('checks', []):
        lines.append(f'| {check["module"]} | {check["function"]} | `{check["expected"]}` | `{check["observed"]}` |')
    lines += ['', '## UNVERIFIED risks and limits', '']
    lines += [f'- {item}' for item in report.get('unverified', [])] or ['- None recorded; absence of limitations was not independently established.']
    lines += ['', '## Input identity', '']
    for name, digest in sorted(report.get('inputs', {}).get('hashes', {}).items()):
        lines.append(f'- `{name}`: `{digest}`')
    lines += ['', 'No devices were accessed and no modules were loaded. Named host KCFI checks do not establish every indirect callback boundary, full nested types or runtime behavior.', '']
    return '\n'.join(lines)


def write_reports(root, report):
    reports = Path(root) / 'reports'
    reports.mkdir(parents=True, exist_ok=True)
    (reports / 'abi-port-verification.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    (reports / 'abi-port-verification.md').write_text(markdown_report(report))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        expectations = default_expectations(root)
        report = verify_tree(root, expectations)
    except Exception as error:
        # A verifier crash/missing prerequisite is still a closed failure report.
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        report = {
            'schema_version': 1, 'generated_utc': datetime.now(timezone.utc).isoformat(),
            'objective_static': 'fail', 'failures': [f'verifier failed closed: {error}'],
            'unverified': ['Verification did not complete; all artifact/runtime properties remain unverified.'],
            'modules': [], 'dependencies': {}, 'load_order': [], 'layout': {},
            'inputs': {'hashes': {}}, 'runtime_verified': False,
        }
        write_reports(root, report)
    print(f'objective_static={report["objective_static"]}; failures={len(report["failures"])}; '
          f'observed_modules={len(report["modules"])}; unverified={len(report["unverified"])}')
    for failure in report['failures']:
        print('FAIL:', failure, file=sys.stderr)
    print(root / 'reports/abi-port-verification.json')
    print(root / 'reports/abi-port-verification.md')
    return 1 if report['objective_static'] == 'fail' else 0


if __name__ == '__main__':
    sys.exit(main())
