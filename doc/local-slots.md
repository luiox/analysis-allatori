# 局部变量槽复用

Allatori 把不同类型的局部变量压进同一槽位:参数槽被后续引用覆写、参数在方法入口被复制到另一个槽,这是反编译输出类型退化的直接根源。9.x 官方 demo jar 入口类 `main` 的 javap 节选(标识符与常量已脱敏,前部死常量块省略为 `…`):

```text
public static void main(java.lang.String[]);
  Code:
     …
     14: aload_0                   // 槽 0:main 的 String[] 参数
     15: astore_1                  // 参数复制进槽 1(局部 a)
     16: new           #15         // class obf2
     19: dup
     20: invokespecial #16         // Method obf2."<init>":()V
     23: astore_0                  // obf2 引用写回槽 0:参数槽被覆盖复用
     24: bipush        -8
     26: ineg                      // 死常量 junk(见 junk-code.md)
     27: aload_0                   // 此后槽 0 恒为 obf2 引用
     …
```

- 槽 0 先持有 `String[]`(参数),又被覆写为 `obf2` 引用;槽 1 存着参数副本,此后不再读取。同一槽先后两种类型,JVM 栈帧的局部变量表只能记录一个验证类型。
- 反编译结果(CFR,同一方法):类型被合并到 `Object` 且不回提升——

```java
Object a;
String[] stringArray2 = a;
a = new obf2();
```

- 反编译器无法用单一声明同时表达 `String[]` 与 `obf2`,只能声明 `Object` 并在使用处强转,可读性尽失。
- 还原面:槽切分(同一槽按定义点拆成多个名字)+ 拷贝传播 + 类型再推断,是把声明恢复为 `String[] args` 与 `obf2` 两个独立变量的路径;该问题属数据流专项,不随字符串解密清偿。
