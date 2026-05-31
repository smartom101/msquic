# MsQuic Linux 编译指南（WSL2 + Ubuntu 22.04）

> 分支：`BBR_V3_From_2.5.8`
> 环境：WSL2 Ubuntu 22.04，代码位于 WSL 原生 ext4 路径（`~/msquic`）

---

## 一、前置条件

- Windows 11 + WSL2 + Ubuntu 22.04
- Windows 宿主机已安装 PowerShell 7（`pwsh`）
- Windows 宿主机运行代理（如 Clash，端口 7890），用于访问 GitHub

---

## 二、代理配置（一次性）

WSL2 用 NAT 网络，宿主机 IP 是默认路由网关。在 WSL 的 `~/.bashrc` 末尾添加：

```bash
function proxy-on {
    host_ip=$(ip route | grep default | awk '{print $3}')
    export HTTP_PROXY="http://$host_ip:7890"
    export HTTPS_PROXY="http://$host_ip:7890"
    export http_proxy="http://$host_ip:7890"
    export https_proxy="http://$host_ip:7890"
    git config --global http.proxy  "http://$host_ip:7890"
    git config --global https.proxy "http://$host_ip:7890"
    echo "代理已开启 ($host_ip:7890) — git + env"
}

function proxy-off {
    unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
    git config --global --unset http.proxy
    git config --global --unset https.proxy
    echo "代理已关闭 — git + env"
}
```

使生效：
```bash
source ~/.bashrc
proxy-on
```

---

## 三、安装工具链

### 3.1 安装 PowerShell（若未安装）

```bash
wget -q "https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb" -O /tmp/pkg.deb
sudo dpkg -i /tmp/pkg.deb
sudo apt-get update -y
sudo apt-get install -y powershell
```

### 3.2 安装编译依赖

```bash
# prepare-machine.ps1 -ForBuild 能装大部分，但漏了 ninja-build
sudo apt-add-repository ppa:lttng/stable-2.13 -y
sudo apt-get update -y
sudo apt-get install -y \
    cmake \
    ninja-build \
    build-essential \
    perl \
    liblttng-ust-dev \
    babeltrace \
    libssl-dev \
    libnuma-dev \
    cppcheck \
    clang-tidy \
    ruby ruby-dev \
    rpm
sudo gem install public_suffix -v 4.0.7
sudo gem install fpm
```

### 3.3 验证工具链

```bash
pwsh --version    # ≥ 7.x
cmake --version   # ≥ 3.23
ninja --version   # ≥ 1.10
gcc --version     # ≥ 11.x
```

---

## 四、首次拉取代码

### 方式一：从 GitHub 直接 clone（需要代理）

```bash
proxy-on
cd ~
git clone https://github.com/你的用户名/msquic.git msquic
cd msquic
git checkout BBR_V3_From_2.5.8
git submodule update --init --recursive
```

### 方式二：从 Windows 本地仓库 clone（推荐，不走网络）

如果 Windows 上已经有一份完整的仓库（含子模块），可以直接从本地克隆，连代理都不需要开：

```bash
cd ~
rm -rf msquic
git clone /mnt/d/Codespace/msquic msquic
cd msquic
git checkout BBR_V3_From_2.5.8
# 子模块还是要从网络拉一次
proxy-on
git submodule update --init --recursive
```

> **原理**：`git clone /mnt/d/... ~/msquic` 只是从 Windows 仓库读取 git 对象（对象永远存 LF），然后 checkout 到 `~/msquic`（ext4）。WSL 下没设 `autocrlf`，文件 checkout 出来就是 LF，不会带 CRLF。

---

## 五、日常 Git 操作

你的工作流：在 Windows IDE 改代码 → WSL 编译验证 → 推到 GitHub。

### 5.1 从 Windows 同步代码到 WSL

```bash
# WSL 里执行，从 Windows 本地仓库直接拉取（不走网络）
cd ~/msquic
git pull /mnt/d/Codespace/msquic BBR_V3_From_2.5.8
```

### 5.2 在 WSL 提交并推送到 GitHub

```bash
proxy-on
cd ~/msquic

# 常规提交流程
git add src/...           # 只加你改的文件，别 git add -A（会把 quictls 的假改动也加进去）
git commit -m "your message"
git push origin BBR_V3_From_2.5.8
```

### 5.3 从 GitHub 拉取远端更新

```bash
proxy-on
cd ~/msquic
git pull origin BBR_V3_From_2.5.8
# 子模块一般不会变，如果变了才执行：
git submodule update --recursive
```

### 5.4 完整周期（改代码 → 编译 → 推送）

```
Windows IDE 改代码
    ↓
WSL: git pull /mnt/d/Codespace/msquic BBR_V3_From_2.5.8   ← 从 Windows 同步
    ↓
WSL: pwsh ./scripts/build.ps1 ...                           ← 编译验证
    ↓
WSL: git add / commit / push origin                         ← 推到 GitHub（要 proxy-on）
    ↓
Windows: git pull                                           ← 同步回 Windows（如果需要）
```

### 5.5 注意事项

- **不要 `git add -A`**：Windows 侧 `autocrlf=true` 会让 quictls 子模块的 4690 个文件显示为 modified，`-A` 会把它们全加进去。只加你自己改的文件。
- **Windows 侧的 quictls 假改动不用管**：那是 filemode + CRLF 导致的 checkout 差异，不是真正的代码变更。WSL 原生路径下子模块始终干净。
- **Git 配置差异**：Windows 设了 `autocrlf=true`（checkout CRLF，commit LF），WSL 没设（checkout LF，commit LF）。两边各编各的平台，互不干扰。

---

## 六、编译

### 6.1 Debug（开发调试用）

```bash
cd ~/msquic
pwsh ./scripts/build.ps1 -Config Debug -Platform linux -Tls quictls -Arch x64
```

产物：`artifacts/bin/linux/x64_Debug_quictls/`

### 6.2 Release（上线部署用）

```bash
cd ~/msquic
pwsh ./scripts/build.ps1 -Config Release -Platform linux -Tls quictls -Arch x64
```

产物：`artifacts/bin/linux/x64_Release_quictls/`

> Release 模式实际使用 `RelWithDebInfo`（`-O2` 优化 + 调试符号），兼顾性能与线上问题定位。

### 6.3 Official Release（打标签版本）

```bash
pwsh ./scripts/build.ps1 -Config Release -Platform linux -Tls quictls -Arch x64 -OfficialRelease
```

### 6.4 常见问题

| 报错 | 解决 |
|------|------|
| `ninja: command not found` | `sudo apt install -y ninja-build` |
| `clog: command not found` | 加 `-DisableLogs` 参数跳过日志编译 |
| 清理重编 | `rm -rf build/linux && pwsh ./scripts/build.ps1 ...` |

---

## 七、常用操作速查

| 操作 | 命令 |
|------|------|
| 开关代理 | `proxy-on` / `proxy-off` |
| 从 Windows 同步代码 | `git pull /mnt/d/Codespace/msquic BBR_V3_From_2.5.8` |
| 从 GitHub 拉取 | `proxy-on && git pull origin BBR_V3_From_2.5.8` |
| 推送 | `git push origin BBR_V3_From_2.5.8` |
| Debug 编译 | `pwsh ./scripts/build.ps1 -Config Debug -Platform linux -Tls quictls -Arch x64` |
| Release 编译 | `pwsh ./scripts/build.ps1 -Config Release -Platform linux -Tls quictls -Arch x64` |
| 跳过日志编译 | 加 `-DisableLogs` |
| 清理重编 | `rm -rf build/linux && pwsh ./scripts/build.ps1 ...` |
| 更新子模块 | `git submodule update --init --recursive` |
| 检查换行符 | `file submodules/quictls/Configure` |

---

## 八、TLS 互通说明

| 平台 | TLS 实现 | 能否互通？ |
|------|----------|-----------|
| Windows (schannel) | SChannel | ✅ 与任一互通 |
| Linux (quictls) | quictls (OpenSSL fork) | ✅ 与任一互通 |

两者都实现标准 TLS 1.3，协议层完全兼容。Windows 客户端（schannel）与 Linux 服务端（quictls）可以正常建立 QUIC 连接。



## 九、win使用openssl

---
  需要安装的工具

    ┌───────────────┬──────────────────────────────────────────┬────────┬─────────────────────────────────────────────┐
      │     工具      │                   作用                   │  检查  │                    下载                     │
      ├───────────────┼──────────────────────────────────────────┼────────┼─────────────────────────────────────────────┤
      │ Strawberry    │ 运行 quictls/Configure 脚本，生成        │ perl   │ https://strawberryperl.com                  │
      │ Perl          │ opensslv.h 等                            │ -v     │                                             │
      ├───────────────┼──────────────────────────────────────────┼────────┼─────────────────────────────────────────────┤
      │ NASM          │ OpenSSL 汇编优化，Configure 时检测       │ nasm   │ https://www.nasm.us/pub/nasm/releasebuilds/ │
      │               │                                          │ -v     │                                             │
      └───────────────┴──────────────────────────────────────────┴────────┴─────────────────────────────────────────────┘

  安装后把两者都加到系统 PATH，并重启 Visual Studio（让新 PATH 生效）。

  安装后把两者都加到系统 PATH，并重启 Visual Studio（让新 PATH 生效）。

  编译必须从 Developer Command Prompt 启动

  OpenSSL 用 nmake 构建，这个命令只在 VS 的 Developer Command Prompt 里有。如果你直接双击 .sln 打开 VS，nmake 不在
  PATH，perl Configure 能跑但 nmake install_dev 会失败，头文件就不会生成。

  正确姿势：

  ### 从"Developer Command Prompt for VS 2019"启动 VS
  devenv D:\Codespace\msquic\build\windows\x64_quictls\msquic.sln

  或者命令行构建（在 Developer Command Prompt 里）：

  cmake --build D:\Codespace\msquic\build\windows\x64_quictls --config Release

  完整步骤（装好工具后）

  1. 安装 Strawberry Perl → 安装时选"Add to PATH"
  2. 安装 NASM → 安装后手动加到系统 PATH
  3. 打开"Developer Command Prompt for VS 2019"
  4. 验证：perl -v  和  nasm -v  都能输出版本
  5. 删除旧 build：Remove-Item -Recurse -Force D:\Codespace\msquic\build\windows\x64_quictls
  6. cmake --preset windows-quictls
  7. cmake --build --preset windows-release

  构建时 OpenSSL 那步会比较慢（几分钟），看到 OpenSSL configure / OpenSSL build 输出就是正常在跑。
