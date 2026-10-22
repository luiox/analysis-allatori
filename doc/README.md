# Allatori 技术笔记

Allatori(商业 JVM 混淆器)的静态特征与技术档案,按技术分篇,是本仓还原 pass 的识别与改写依据。样例均取自官方 demo jar(9.x)的 javap 与反编译输出;实现契约(扫描、求值、改写、兜底)见源码头注释,不在文档重复。

- `versions.md`:版本台账——类版本、名称残留、8.x 与 9.x 的观测差异。
- `string-encryption.md`:字符串加密——调用点形态、解密器识别判据、fast/strong 两形态、native 与双层链。
- `renaming.md`:重命名——命名风格、demo 标记、关键字成员名。
- `local-slots.md`:局部变量槽复用——字节码形态与反编译类型退化。
- `junk-code.md`:死代码与 opaque 注入——死常量块、未折叠常量表达式、恒假分支。
