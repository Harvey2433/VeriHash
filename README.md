# VeriHash

VeriHash 1.2.0 是一个用于计算和校验文件摘要的交互式命令行程序, 支持
Windows, Linux 和 macOS. 程序目前不提供非交互式命令行参数, 直接运行可执行文件
后按终端提示操作.

## 功能范围

- 计算单个文件, 递归目录或通配符匹配结果的摘要.
- 从指定源目录发现校验清单, 也可手动指定源目录外的清单.
- 多算法计算共用同一次文件读取, 各算法消费同一块输入数据.
- 使用有界任务队列, 按卷调度, 可复用缓冲区和原子进度计数处理文件.
- 计算结果先写入磁盘临时数据流, 不要求将全部结果保存在内存中.
- 可选导出计算清单, 校验报告和性能诊断报告.

Windows 路径使用独立的异步读取实现, 包括 IOCP, 对齐缓冲区, 无缓冲读取尝试,
有序预读和按存储设备调整的并行限制. 无缓冲读取不可用时会回退到缓存读取.
Linux 路径使用 io_uring 缓存异步读取和有序多请求流水线, io_uring 不可用时回退到
polling 后端. macOS 使用标准文件接口. 三个平台共享上层扫描, 哈希, 调度和输出逻辑.

项目没有在 README 中给出固定性能数字. 吞吐量取决于文件分布, 所选算法, CPU,
文件系统, 存储设备, 接口和同时发生的其他 I/O. 需要比较版本时, 可在相同输入和
运行环境下启用程序末尾的性能报告.

## 支持的算法

- MD5
- SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
- SHA3-224, SHA3-256, SHA3-384, SHA3-512
- BLAKE2s, 输出长度为 8 到 256 位且为 8 的倍数
- BLAKE2b, 输出长度为 8 到 512 位且为 8 的倍数
- BLAKE3-256

计算模式默认选择 MD5 和 SHA-256. 算法可以在交互界面中多选.

## 输入与输出

计算模式接受单个文件, 目录, 相对路径, 绝对路径和通配符. 文件数不超过 10 时,
程序先按算法显示结果, 再询问是否写入文件; 文件数超过 10 时, 直接进入输出格式
选择.

可同时选择以下输出格式:

- `BlazeHash Compatible`: 写入 `checksums.blazehash`, 使用
  `%%%% HASHDEEP-1.0` 表头以及 size, 摘要和 filename 列.
- `VeriHash Grouped`: 写入 `checksums.verihash`, 记录按算法分组, 算法组之间保留空行.
- `GNU sumfiles`: 每种算法写入一个二进制模式清单, 例如 `md5sums` 和
  `sha256sums`.

校验模式首先输入校验源目录. 程序会在该目录中检测 BlazeHash Compatible,
VeriHash Grouped, GNU sumfile 和单文件 sidecar 清单; 未发现清单时再要求手动输入
清单路径. 校验结束后可导出独立的 `verification-report.txt`.

## 环境要求

- Rust 1.85 或更高版本. 项目使用 Rust 2024 edition.
- Git.
- 对应目标平台的系统链接器. 具体要求见下方各平台命令.

安装最新 stable 工具链:

```text
rustup toolchain install stable
rustup default stable
rustc --version
cargo --version
```

## 快速构建

在当前平台构建 release 版本:

```text
git clone https://github.com/Harvey2433/VeriHash.git
cd VeriHash
cargo build --locked --release
```

运行:

```text
cargo run --locked --release
```

产物位于 `target/release/verihash`; Windows 文件名为
`target\release\verihash.exe`.

开发检查:

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

## Windows 构建

MSVC 目标需要 Visual Studio 2022 Build Tools, 并安装 Desktop development with C++
工作负载和相应架构的 MSVC 工具. x86-64 构建命令:

```text
rustup target add x86_64-pc-windows-msvc
cargo build --locked --release --target x86_64-pc-windows-msvc
```

Windows on ARM 构建命令:

```text
rustup target add aarch64-pc-windows-msvc
cargo build --locked --release --target aarch64-pc-windows-msvc
```

产物位于 `target\<target>\release\verihash.exe`.

## Linux 构建

Debian 或 Ubuntu 上先安装 GNU 链接器, 然后构建 x86-64 GNU 目标:

```text
sudo apt-get update
sudo apt-get install -y build-essential
rustup target add x86_64-unknown-linux-gnu
cargo build --locked --release --target x86_64-unknown-linux-gnu
```

在 ARM64 Linux 主机上构建:

```text
sudo apt-get update
sudo apt-get install -y build-essential
rustup target add aarch64-unknown-linux-gnu
cargo build --locked --release --target aarch64-unknown-linux-gnu
```

需要 musl 目标时, 在 x86-64 Debian 或 Ubuntu 上执行:

```text
sudo apt-get update
sudo apt-get install -y musl-tools
rustup target add x86_64-unknown-linux-musl
cargo build --locked --release --target x86_64-unknown-linux-musl
```

产物位于 `target/<target>/release/verihash`.

## macOS 构建

先在 macOS 安装 Apple Command Line Tools:

```text
xcode-select --install
```

Apple Silicon 构建命令:

```text
rustup target add aarch64-apple-darwin
cargo build --locked --release --target aarch64-apple-darwin
```

Intel Mac 构建命令:

```text
rustup target add x86_64-apple-darwin
cargo build --locked --release --target x86_64-apple-darwin
```

在 macOS 上生成同时包含两个架构的通用二进制:

```text
rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo build --locked --release --target aarch64-apple-darwin
cargo build --locked --release --target x86_64-apple-darwin
lipo -create -output target/verihash-macos-universal \
  target/aarch64-apple-darwin/release/verihash \
  target/x86_64-apple-darwin/release/verihash
```

从 Windows 或 Linux 构建 macOS 目标仍需要合法取得的 Apple SDK 和可用的 Darwin
链接器. 本仓库没有附带这些组件, 因此不提供假定它们已经存在的命令.

## 交叉构建

安装 Zig 和 `cargo-zigbuild` 后, 可从 Windows, Linux 或 macOS 构建 Linux GNU
目标:

```text
cargo install --locked cargo-zigbuild
rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
cargo zigbuild --locked --release --target x86_64-unknown-linux-gnu
cargo zigbuild --locked --release --target aarch64-unknown-linux-gnu
```

从 Debian 或 Ubuntu 构建 64 位 Windows GNU 目标:

```text
sudo apt-get update
sudo apt-get install -y mingw-w64
rustup target add x86_64-pc-windows-gnu
cargo build --locked --release --target x86_64-pc-windows-gnu
```

交叉构建只能证明目标可以完成编译和链接. 发布前仍应在对应操作系统和架构上运行
测试, 并实际启动 release 二进制.

## 模块

- `algorithm`: 算法标识, 别名, 摘要长度和摘要值.
- `scanner`: 文件, 目录和通配符发现, 以及磁盘任务计划.
- `hashing`: 流式多算法计算和平台读取实现.
- `scheduler`, `concurrency`, `io_feedback`: 任务执行, 并发控制和 I/O 反馈.
- `progress`: 进度计数与终端渲染.
- `spool`: 临时元数据和摘要数据流.
- `format`: 三种输出格式以及清单检测.
- `verify`: 清单合并, 冲突检测, 并行校验和校验报告.
- `app`, `interaction`: 交互流程和终端样式.
- `performance`: 可选性能诊断数据采集和报告.

## 许可证

VeriHash 使用 ISC License. Copyright (c) 2026 Maple Bamboo Team. 完整文本见
[`LICENSE`](LICENSE).
