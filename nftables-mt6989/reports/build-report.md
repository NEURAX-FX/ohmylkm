# Build report — final bounded native Kbuild

## 已成功执行

实际本轮 `python3 scripts/build.py`（与 build.sh 的 Python 入口相同）完成；原生 Kbuild 目标 **16/16 exit 0**。清单 `abi-port-build-results.json`，每个实际展开命令及状态 `logs/build-*-4.log` / `.status`。prepare 的 `olddefconfig` / `modules_prepare` 均成功：`logs/abi-port-{olddefconfig,modules-prepare}-3.log`。全部使用 `-j2`。

构建文件位于 `../output/abi-port/`，含 `nf_tables.ko` 和完整所选 CT/NAT/MASQ/LIMIT/LOG/REDIR/FIB/REJECT 集合。`NFT_NAT=m` 所需的 `nft_nat.ko`、`nft_chain_nat.ko` 均成功。最终 probe：`logs/abi-port-layout-probe-2.log`，编译 exit 0，`-j2`。

静态验证 `sh scripts/verify.sh` 实际结果：PASS / 0 failures / 16 observed modules；375 CRC records、359 strong-import checks、64 genuine new exports、9 个宿主接口结构对比通过；5 个宿主 named KCFI 类型字匹配。完整永久测试 21/21 通过，真实 NAT 适配主机烟测通过，且没有把模拟宿主接口当成 packet-path 证明。

## 构建固定条件与修复

- 源码 commit `b1ea2c8ce2ef0f73927a593aa450f88143e3584a`；vendor `e7320c9131c8fa539dc0e3899e7c81eba901da21`，用于解决原树 vendor symlink/build prerequisites。
- Android Clang r487747c / 17.0.2。工具链、RPM 和兼容 HOSTCC headers 的精确 URL/SHA256 均已 pin 于 inputs JSON。未使用 Android NDK。
- 原宿主 `.config` 和 Module.symvers 来源及 Image 恢复交叉验证见 README、manifest 与 `boot-image-evidence.json`。原始用户表、原始源码及 pristine work/kernel 未覆盖。
- 主机缺 pahole/flex/bison/bc 时下载 pin 的 RPM 到 work/ 并非系统安装；openssl-devel-engine 补 engine.h；兼容 glibc 2.41 host headers 解决新主机头文件 const-generic strchr 与旧 host libbpf 的 Werror 冲突，未关闭 Werror。
- 源码隔离副本 `work/kernel-abi-port/` 应用两项已固定补丁：私有 generation state 保持宿主 net 布局；inet NAT 使用原宿主 family 导出及 per-chain ops。没有手动链接 .ko、忽略 modpost、改写 CRC 或 Hook 宿主。
- 公共源码 olddefconfig 删除不可识别的 KSU/SUSFS 选项；不冒充完整目标下游源码。最终配置和 diff 为 `abi-port.config`、`abi-port-config.diff`，所选 nft fragment 保留且 conntrack/NAT flags 不变。

## 资源限制与复现

`JOBS` 默认 2，只允许 1 或 2。其他值在 make 前拒绝。布局转换 pahole 固定 `-j1`。不执行全内核构建。原始失败日志仍保留，以免把旧 -j8 失败当成本轮结果。

```sh
JOBS=2 ./nftables-mt6989/scripts/prepare.sh
JOBS=2 ./nftables-mt6989/scripts/build.sh
./nftables-mt6989/scripts/verify.sh
python3 -m unittest discover -s nftables-mt6989/tests -v
```

已有最终生成目录时脚本拒绝覆盖；重建前先移走 `work/build-abi-port/` 和 `output/abi-port/` 以保留已有证据。在当前交付目录仅执行 verify.sh 不会重编或加载。

最终哈希绑定：`abi-port-artifact-sha256.json`、`abi-port-layout-inputs.json`。构建自动输出 dependencies 和 probe；verify 独立解析实际符号/重定位，绝不因缺工具跳过。没有原始 vmlinux ELF，Kbuild 如实跳过 .ko BTF；probe 的临时 BTF 只来自实际 DWARF。

## 历史与边界

初始原样源码构建 15/16 成功，inet NAT 在 modpost 被拒绝且 net 布局不兼容；旧 artifacts 保留 `output/incompatible/`。中途部分错误来自不必要的类型检查声明，已删除，错误日志保留。新 ABI 移植结果见前述本轮日志，旧报告中的原样源码限制不再被当成新产物状态。

没有设备访问、模块加载、boot/分区刷写、SELinux/网络策略/内核内存修改或提交/推送。仅完成编译和静态必要条件检查，真机加载与 firewall4/NAT/netns 行为留待另行授权。没有新增 CI 流程。
