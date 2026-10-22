# 版本台账

- 类文件版本 49(Java 5 目标),8.x 与 9.x 样本一致。
- 8.x:`com/allatori/StackTrace`、`Obfuscate` 等原名残留,疑似混淆排除表未覆盖;存在非 synthetic 的真解密器(`StackTrace` 本身),识别判据因此不得依赖 ACC_SYNTHETIC。
- 9.x:字符串加密分 off/fast/strong 三档,off 不注入、fast 用形态 A、strong 用形态 B(见 string-encryption.md);9.9 官方 demo 出现 Java 关键字成员名(见 renaming.md)。
- 解密器 key 在已观测样本中全为常量表达式:fast 为常量双 key,strong 为常量单 key 叠加调用方上下文;未见运行期派生 key。
