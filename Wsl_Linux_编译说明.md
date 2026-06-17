---
  环境层（WSL 本身）

  第 1 步：开启 WSL2（Windows 11 已内置，用管理员 PowerShell 跑一行）
  wsl --install -d Ubuntu-22.04
  装完重启，按提示设 Linux 用户名/密码。推荐 Ubuntu 22.04，因为 CI（.github/workflows/build-reuse-unix.yml:35）用的就是这个版本，兼容性最好。

---
  工具层（WSL 里安装）

  进入 WSL 后，依次运行：

  1. PowerShell（build.ps1 需要）
  # 一键安装 PowerShell
  wget -q "https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb" -O /tmp/pkg.deb
  sudo dpkg -i /tmp/pkg.deb
  sudo apt-get update -y
  sudo apt-get install -y powershell

  2. 编译工具链（来自 scripts/prepare-machine.ps1:534-551，这是 CI 用的确切包列表）

       ```sudo apt-add-repository ppa:lttng/stable-2.13 -y
        sudo apt-get update -y
         sudo apt-get install -y \
       cmake ninja-build \
       build-essential \
       perl \
       liblttng-ust-dev babeltrace \
       libssl-dev libnuma-dev \
       cppcheck clang-tidy \
       ruby ruby-dev rpm
         sudo gem install public_suffix -v 4.0.7
         sudo gem install fpm
       ```

  ▎ 注意：cmake 包不含 ninja，要单独装 ninja-build（preset 用 Ninja 生成器）。

---
  代码层（子模块）

  Windows 上你已经拉了 quictls 子模块，WSL 直接访问 Windows 路径编译，不需要重新 clone：

  # WSL 里 Windows 的 D 盘挂在 /mnt/d  构建命令
```
cd ~/msquic
# debug
pwsh ./scripts/build.ps1 -Config Debug -Platform linux -Tls quictls -Arch x64
# release
pwsh ./scripts/build.ps1 -Config Release -Platform linux -Tls quictls -Arch x64

#或用 cmake preset（效果相同）：
cmake --preset linux-quictls-debug
cmake --build build/linux/x64_quictls
```

---
  **一个注意点：/mnt/d 性能**

  WSL 访问 Windows NTFS 路径（/mnt/d/...）的 I/O 比在 Linux 原生文件系统慢，影响 quictls 的编译时间（OpenSSL 编译要处理大量小文件）。如果觉得太慢，可以把代码 clone 到 WSL
  原生路径（~/msquic），那里用的是 ext4，速度快很多。

  你现在可以先装 WSL2 + Ubuntu 22.04，装完告诉我，我帮你确认环境是否就绪。



```
直接用 /mnt/d/ 路径,WSL 可以直接访问 Windows 文件系统:

首次 clone:
git clone /mnt/d/MDIDS_GIT/open_source ~/open_source

如果已经 clone 过,拉取最新:
cd ~/open_source
git pull

```

