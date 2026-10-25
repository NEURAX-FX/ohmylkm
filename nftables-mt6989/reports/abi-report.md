# ABI report — adapted module set

## 实际通过

`output/abi-port/` 共 16 个 `.ko`；`scripts/verify.sh` 对真实文件检查结果为 PASS / 0 failures。原始宿主符号表不变。完整数据与每个 artifact SHA256：`abi-port-verification.json`。

- AArch64 ELF64 little-endian ET_REL；精确 vermagic；GPL license；每个 `__this_module` section 和符号大小均 1088。
- 375 条版本记录、359 项强未定义导入的 provider/CRC/GPL/namespace 检查通过；同批 64 项新导出与各自 ELF 的 PREL32 relocation/CRC 匹配。无重复宿主导出，无缺失依赖或依赖环。
- 新探针由与模块相同的 Kbuild 配置和 patched headers 以 `-j2` 编译。pahole `-j1` 将探针实际 DWARF 转为临时 standalone BTF，与恢复的目标 BTF 比较：

| 结构 | 大小 | 命名直接成员 | 大小/位偏移/位域宽度 |
|---|---:|---:|---|
| module | 1088 | 70 | 匹配两个目标 BTF 定义 |
| net | 4096 | 47 | 全匹配，无 nft 成员 |
| netns_nf | 224 | 9 | 匹配 |
| netns_ct | 216 | 9 | 匹配 |
| nf_conn | 272 | 16 | 匹配 |
| nf_conntrack_net | 184 | 7 | 匹配 |
| nf_ct_ext | 16 | 4 | 匹配 |
| nf_hook_state | 48 | 7 | 匹配 |
| nf_hook_ops | 40 | 7 | 匹配 |

`net.wext_nlevents=2760`、`net.gen=2784`、`net.bpf=2792` 字节，与 supplied boot BTF 相同。旧未适配版本的三个偏移 +16 问题由私有 per-net generation 存储补丁消除。旧对比证据保留在 `layout-comparison.json`、`boot-image-evidence.json`；它们描述旧 `output/incompatible/`，不代表新产物失败。

宿主 Image 的 `function_address - 4` KCFI 类型字与模块内 named type ID 比较：`delayed_work_timer_fn=0x91b4a83a`；IPv4/IPv6 NAT register `0xd10b0487`、unregister `0x45e149d0`，5/5 匹配。Image 与 kallsyms SHA256 固定于 manifest。模块间已有 named KCFI ID 相同；这不覆盖所有函数指针回调。

ABI 配置保留 MODVERSIONS、CFI_CLANG、非 permissive CFI、LTO_NONE、DEBUG_INFO_BTF、DEBUG_INFO_BTF_MODULES；MODULE_SIG_FORCE=n。原始 conntrack/NAT feature flags 未漂移。

## 源码复核与主机烟测

两项补丁只用于隔离副本：完整源码 pin 校验后，对 5 个修改文件重建“原始 blob + 精确补丁”并逐字节比较；额外改动的负向烟测已检出。见 `abi-port-source-smoke.json`。

NAT 状态位于每条 inet base chain 的分配内；复制的 family ops 生命周期与 chain 一致。core 注册/注销确实传 `&basechain->ops`；仅 inet NAT chain 请求扩大的分配，其他 chain 保留原尺寸。原生 per-net transaction mutex、NAT mutex/RCU 和 chain teardown 屏障保留。IPv6 失败不遗留注册；IPv4 失败注销原 IPv6 指针；成功注销顺序 IPv4→IPv6。主机模拟接口对实际适配函数完成这三个路径、双 namespace/chain 和 100 次重新注册烟测；见 `abi-port-lifecycle-smoke.json`。不把模拟接口结果当作内核运行证明。

## 仍未验证，不能宣称可安全加载

没有加载任何模块。匹配的是用户提供的 boot.img，不是远程识别正在运行的手机。完整下游源码、所有嵌套类型/回调 KCFI、签名及运行时策略未证明。旧 public-source olddefconfig 删除 KSU/SUSFS keys 的差异仍在。

`.ko` 无 `.BTF`：缺原始 vmlinux ELF，原生 Kbuild 明确跳过。`DEBUG_INFO_BTF_MODULES=y` 仍保留，`struct module` 因此保持 1088；`kernel/bpf/btf.c:7117` 对零模块 BTF 直接略过，且目标 MODULE_ALLOW_BTF_MISMATCH=y。离线探针 BTF 不被写入 `.ko`。无 BTF 不是已观察到的加载阻塞，但类型元数据能力缺失且运行安全未验证。

结论：原生源码的两个确定静态阻塞点已经移植消除，本批模块具备已检查的必要静态条件；不能由此断言手机当前运行环境、fw4/NAT 数据面或加载/卸载均安全。
