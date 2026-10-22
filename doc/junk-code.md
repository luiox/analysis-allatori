# 死代码与 opaque 注入

Allatori 在方法体内注入不改变语义的垃圾指令与恒假分支,抬升阅读成本、干扰模式识别。9.x 官方 demo jar 的实测形态(javap 原文):

## 死常量块

方法头部与语句之间成对出现,栈平衡、无副作用:

```text
public Main();
  Code:
     0: sipush        -22449
     3: sipush        -27677
     6: sipush        32308
     9: sipush        -4623
    12: pop2
    13: pop2
    14: aload_0
    15: invokespecial #9       // Method java/lang/Object."<init>":()V
```

- 形态一:`sipush×4 + pop2×2` 前奏(四个 int 压栈、两个 pop2 成对丢弃)。
- 形态二:语句间 `iconst_1 dup pop2`、`sipush×2 iand` 等平衡对。
- 形态三:float junk,`fconst_2/fconst_1/pop`。
- 清偿:栈平衡即 DCE 可全清。

## 未折叠常量表达式

javac 会折叠的常量运算被替换为指令序列,反编译呈现为算式:

```text
24: bipush        -3
26: ineg                // "--3" 渲染:双 neg
44: iconst_3
45: ixor                // "(2 ^ 3)"
46: sipush        4028
49: sipush        29039
52: iand                // "0xFBC & 0x716F"
```

- 典型落点:`setSize(0xFBC & 0x716F, 0x257E & 0x5BAD)` 这类实参位置。
- 清偿:常量折叠 + 代数化简(双 neg 消除、xor/and 常量传播)。

## opaque 谓词与死分支

```java
switch (keyCode) {
    …
    if (ThreadsController.false == (1 ^ 3)) break;   // 恒假:static int false ≠ 2
    … = 3 & 5;
    return;
}
while (false) { }                                     // 死循环体
```

- 谓词读一个关键字命名的 static int 字段(`false`)与常量表达式(`1 ^ 3` = 2)比较,字段值恒不相等,分支恒假但字节码层面不可平凡判定(需字段值分析)。
- 清偿:opaque 谓词求值(常量传播 + 字段终值分析)后走 DCE;谓词本身即未折叠常量表达式,与上一节联动。
