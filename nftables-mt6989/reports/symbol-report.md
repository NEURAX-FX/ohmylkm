# Symbol and dependency report — adapted modules

## 已观察到的导出与版本

- 宿主：原始恢复 `inputs/Module.symvers` 共 15242 行，SHA256 `fab1af59397cb4c2dfc900f0c08e5ee32f660d6aa9113481528fa9c1d0f71a96`。它与 boot Image 独立恢复结果逐字节一致，15242/15242 导出地址与 Image kallsyms 一致；不是重新编译出的宿主表。
- 模块：`abi-port-built-module-exports.symvers` 共 64 项真实 modpost 导出，与本批 ELF 的 __ksymtab PREL32 relocation、对应 __crc 符号及 GPL/namespace 属性逐项一致；没有伪造原宿主 CRC。
- 验证 16 个模块累计 375 条 `__versions`、359 项强未定义导入。`module_layout` CRC 为 `0xea759d7f`；每个版本 record 为 ARM64 64 字节格式，记录长度、重复/遗漏、provider、CRC、GPL 与 namespace 失败均会拒绝。所有检查通过。

## inet NAT 原宿主限制与兼容适配

原宿主确实不导出 `nf_nat_inet_register_fn` 和 `nf_nat_inet_unregister_fn`。未适配 `nft_chain_nat.ko` 的旧 modpost 失败日志保留，失败未被压制。

新模块不再引用这两个名字，也没有在新符号表中伪造它们。使用真实宿主导出：

| 函数 | 原宿主 CRC | Image KCFI 类型字 |
|---|---|---|
| nf_nat_ipv4_register_fn | `0xd1744474` | `0xd10b0487` |
| nf_nat_ipv4_unregister_fn | `0x60b00c8b` | `0x45e149d0` |
| nf_nat_ipv6_register_fn | `0x95d7e7af` | `0xd10b0487` |
| nf_nat_ipv6_unregister_fn | `0x4da3a6ae` | `0x45e149d0` |

inet base chain 各自持有稳定 family ops 副本，明确设置 IPv4/IPv6 pf，保留原始 hook/priv/priority；没有错误地把 NFPROTO_INET ops 原样交给按 ops->pf 索引的 family wrapper。注册/回滚/注销语义见 ABI 报告。

## 实际依赖图

`output/abi-port/modules.dep` 由真实 `.modinfo depends` 生成，严格 verifier 再用实际导入 provider 独立核验。全图无缺失依赖或环。

- 所有扩展在 `nf_tables` 之后。
- `nft_fib_ipv4/ipv6` 在 `nft_fib` 之后；`nft_fib_inet` 还依赖这两个 family 模块。
- REJECT family/inet 在 `nft_reject` 之后。
- `nft_chain_nat` 依赖 `nf_tables`；`NFT_NAT=m` 下它与 `nft_nat` 都已构建成功，不能只拿后者声称 inet NAT 完整。

本批原始模块内部 ABI 已因兼容移植变化，必须整批使用，不与旧 output/incompatible 模块混用。依赖顺序仅供后续人工加载审查，不在本轮执行加载。

完整每模块导出、导入、版本记录计数、namespace、KCFI ID 和 SHA256 在 `abi-port-verification.json`。静态解析通过不证明内核加载或 packet-path 行为。
