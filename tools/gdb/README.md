# tools/gdb — 静态 gdb 工具链

给 `cybergym_gdb` 用的**静态编译 gdb**。单一文件、无 glibc 依赖，以只读卷挂载进任意任务的
dynamic-whole 容器（`/opt/gdb`），因此不依赖任务镜像自身是否带 gdb（实测绝大多数 arvo /
oss-fuzz 镜像都不带）。

## 版本

| 文件 | 版本 | 用途 |
|---|---|---|
| `bin/gdb-13` | gdb 13.2 | 主力：完整支持 clang 18 的 DWARF5（oss-fuzz 镜像，Ubuntu 20.04） |
| `bin/gdb-8.3` | gdb 8.3.1 | 备用：老环境兼容性兜底 |

选版逻辑：`cybergym_gdb --gdb-version auto`（默认）优先 `gdb-13`，缺则回落 `gdb-8.3`；
也可显式 `--gdb-version 13|8`。

## 构建

```bash
sudo bash ~/netunlock.sh          # 构建需要网络（apt + gnu.org）
bash fetch.sh                     # 编译 gdb-13 + gdb-8.3（docker + ubuntu:20.04）
sudo bash ~/netlock.sh
```

产物是纯静态二进制（`file bin/gdb-*` 应显示 `statically linked`），不依赖容器内 libc。

## 验证

```bash
file bin/gdb-13                    # statically linked
docker run --rm -v "$PWD/bin:/opt/gdb:ro" cybergym/oss-fuzz:385170375-vul \
  /opt/gdb/gdb-13 --version | head -1
```

## 说明

- 二进制与编译中间产物（`bin/`、`build/`）已在 `.gitignore`，不进仓库；本 README 与
  `fetch.sh` 入库。
- 容器内 gdb 只能调试 **vul 侧**（容器为 vul-only 镜像，无 fix 信息）。
- 大二进制（30MB+）符号加载慢：`cybergym_gdb --timeout` 默认 120s，可调至 600。
