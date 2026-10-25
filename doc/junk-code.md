# 死代码与 opaque 注入

Allatori 在方法体内注入不改变语义的垃圾指令与恒假分支,抬升阅读成本、干扰模式识别。9.x 官方 demo jar 的实测形态(javap 节选,标识符与常量已脱敏):

## 死常量块

方法头部与语句之间成对出现,栈平衡、无副作用:

```text
public obf1();
  Code:
     0: sipush        11111
     3: sipush        -22222
     6: sipush        31313
     9: sipush        -4141
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
24: bipush        -8
26: ineg                // "--8" 渲染:双 neg
44: iconst_1
45: ixor                // "(2 ^ 1)"
46: sipush        4369
49: sipush        8738
52: iand                // "0x1111 & 0x2222"
```

- 典型落点:`setSize(0x1111 & 0x2222, 0x4444 & 0x8888)` 这类实参位置。
- 清偿:常量折叠 + 代数化简(双 neg 消除、xor/and 常量传播)。

## opaque 谓词与死分支

```java
switch (keyCode) {
    …
    if (obf3.false == (1 ^ 3)) break;   // 恒假:static int false ≠ 2
    … = 3 & 5;
    return;
}
while (false) { }                                     // 死循环体
```

- 谓词读一个关键字命名的 static int 字段(`false`)与常量表达式(`1 ^ 3` = 2)比较,字段值恒不相等,分支恒假但字节码层面不可平凡判定(需字段值分析)。
- 清偿:opaque 谓词求值(常量传播 + 字段终值分析)后走 DCE;谓词本身即未折叠常量表达式,与上一节联动。
