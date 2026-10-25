# 重命名

## 命名风格

- 混淆名为 10 字符的 i/I 排列(如 `iIiiIIIIiI`);8.x 观测类名同样被替换,9.x 官方 demo 类名保持原名,只混淆成员与局部变量。
- 名字之间仅大小写差异,大小写不敏感文件系统上落盘会互撞,处理时须按归档内原名内存直读。
- demo 构建把部分重命名标识符直接替换为 `THIS_IS_DEMO_VERSION_NOT_FOR_COMMERCIAL_USE`,类/方法/字段均可见,是最醒目的 demo 特征;商用构建无此标记,只能按结构识别。

## 关键字成员名

成员名直接使用 Java 关键字,字段与方法都出现,同名方法按重载并存。9.x 官方 demo jar 的 javap 成员表(节选,类名已脱敏,占位符见各文档):

```text
public final class obf4 {
  int byte;
  java.util.ArrayList enum;
  obf5 do;
  public void true(int);
  public obf4(int);
  public static java.lang.String true(java.lang.String);
}

public final class obf3 extends java.lang.Thread {
  java.util.ArrayList catch;
  java.util.ArrayList super;
  public static int false;
  obf6 break;
  obf6 byte;
  int enum;
  long do;
  private void true(int);
  private void super();
  private void final();
  private obf6 true();
  private void this();
  private void true(obf6);
  public void run();
  private void break();
  private void true();
}
```

- 关键字名对源码级工具免疫:javac 直调报"找不到符号",反编译器输出含不可再编译的成员名。
- 局部变量为单字母 `a`/`a2` 风格,配合槽复用造成反编译类型退化(见 local-slots.md)。
- 还原面:关键字名无语义,按"关键字 → 语义名"词典规范化,重载靠描述符区分。
