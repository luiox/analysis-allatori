# deobf-allatori

## What it is

Allatori 混淆家族的 deobf 插件仓：mjbase pass-pack 静态链接 + 独立 CLI。输入混淆 jar，输出还原 jar。无宿主进程、无动态库边界，ABI 面不存在；pack 与 CLI 同源构建，跨仓混装产物由 mjbase 同源门拒绝。

## Build

需要本地 mjbase 检出且含 plugin 接口（plugin-api 分支及以上），默认找 `../mjbase-plugin-api`，用 `MJBASE_DIR` 覆盖：

```sh
MJBASE_DIR=/d/WorkSpace/mjbase-plugin-api xmake f --with_tests=y
xmake build allatori_cli
```

## Run

```sh
xmake run allatori_cli -- -i in.jar -o out.jar -p allatori.X -c pack.json
```

`-p` 逗号分隔 pass 名（`allatori.` 前缀），`-c` 可选，pack 配置 JSON 文本文件；`--list` 列出全部可用 pass。

## Test

```sh
xmake build allatori_unittest && xmake run allatori_unittest
```

集成用例读环境变量 `ALLATORI_LAB_DIR`（指向含 obf-fast.jar / obf-strong.jar 语料的目录），未设置时自动跳过。

## Doc index

`doc/` Allatori 技术档案：`versions.md` 版本台账、`string-encryption.md` 字符串加密、`renaming.md` 重命名、`local-slots.md` 槽复用、`junk-code.md` 死代码与 opaque。
