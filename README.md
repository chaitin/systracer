# SysTracer: Linux 系统活动跟踪器

![build](https://github.com/chaitin/systracer/actions/workflows/build.yml/badge.svg)
![release](https://img.shields.io/github/release/chaitin/systracer)
![update](https://img.shields.io/github/release-date/chaitin/systracer.svg?color=blue&label=update)

SysTracer 是长亭所开发的，用于跟踪 Linux 关键活动的监控程序。

得益于 Linux Tracing 技术和内核分析手段，SysTracer 的监控和跟踪是事件驱动且实时的。

![](https://github.com/chaitin/systrace-blob/raw/7a79506047ea3baf7b6b41d3318dfde438e89b34/screenshot.gif)

<p align="center"><i>使用 SysTracer 监控 Docker Pull+Run 时的网络和文件活动</i></p>

## 功能和使用方法

各 CPU 架构下的 SysTracer 的可执行文件（静态编译）可以在 [Releases](https://github.com/chaitin/systracer/releases) 页面下载，请注意验证文件完整性。

执行 SysTracer 需要 root 权限，但 SysTracer 不会在系统上创建持久化文件或修改系统配置。

### 网络活动监控

当前 SysTracer 支持基于 IPv4 和 IPv6 的网络连接和网络监听活动的监控。

网络连接监控基于进程通过 `connect` 系统调用发起远程连接的跟踪，记录了进程用于发起远程连接的主动套接字 FD，远程连接的协议（TCP 或 UDP 等）以及远程服务器的地址。

网络监听监控基于进程通过 `listen` 系统调用发起网络监听的跟踪，记录了进程用于监听的被动套接字 FD，监听的网络地址以及 Backlog 大小。

通过 `./systracer --connect` 或 `./systracer --all` 可以启用对网络连接的监控，通过 `./systracer --listen` 或 `./systracer --all` 可以启用对网络监听的监控。

### 文件操作递归监控

当前 SysTracer 支持对文件操作进行递归监控，即用户指定监控目录和所关心的事件集合，SysTracer 输出在监控目录下发生的文件事件。

所谓递归监控是指，不仅监控指定的监控目录下的文件事件，还监控其子目录及所有后代目录的下发生的文件事件。

当前支持的文件操作包括：（文件、目录）创建、（文件、目录）删除、移动或重命名、属性（权限、所有用户、所有组）修改、创建符号连接、创建硬连接。

如果同时指定了具有父子关系的监控目录（如 `/usr` 和 `/usr/lib`），则子目录的事件集合将覆盖父级目录的，父级目录下的其他目录不受影响。

通过 `./systracer --watch "<events>=<path>"` 可以添加一个监控目录，如 `./systracer --watch "all=/etc"`。

参数中的 `events` 指定了监控事件的列表，可以为以下事件的集合，事件之间通过 `,` 分隔：

- `all`：监控所有支持的文件事件。
- `create`：监控普通文件的创建，输出创建的文件路径和权限。
- `mkdir`：监控目录的创建，输出创建的目录路径和权限。
- `mknod`：监控特殊文件（管道、套接字、字符设备、块设备等）的删除，输出创建的文件路径、权限和设备 ID。
- `delete`：监控文件的删除，输出删除的文件路径。
- `rmdir`：监控目录的删除，输出删除的目录路径。
- `rename`：监控文件或目录的移动或重命名，输出重命名前后的文件路径。
- `attrib`：监控文件或目录属性（权限、所有用户、所有组）的修改，输出修改的文件路径和属性。
- `symlink`：监控符号连接的创建，输出软连接的内容和软连接的路径。
- `link`：监控硬连接的创建，输出链接的源路径和目标路径。

譬如 `./systracer --watch "all=/usr" --watch "create,mkdir=/usr/lib"` 就同时添加了对 `/usr` 目录下所有支持的文件事件的递归监控，以及 `/usr/lib` 目录下文件和目录创建事件的递归监控。

值得注意的是，SysTracer 只会上报已经成功完成的文件操作事件。

## 许可协议

本项目基于 [Apache-2.0](LICENSE) 协议进行开源和许可。
