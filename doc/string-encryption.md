# 字符串加密

## 调用点形态

- 唯一调用形态:`ldc <密文>` 与 `invokestatic <解密器>` 序相邻,解密器描述符固定 `(Ljava/lang/String;)Ljava/lang/String;`;消费方不限于 StringBuilder.append,也可能是 String.replaceAll 或普通传参。
- ldc 与调用紧邻是识别锚点:ldc 前置边界被存活标签(分支目标/异常表/调试边界)锚定时,该点不参与加密。
- 同一方法内可双层连调:上层(通常 strong)的输出紧邻再进下层(通常 weak);上层输出是中间态密文,常含 C0 控制符与未配对代理项。也存在两个解密器各产同一消费调用的一个参数的形态。

## 解密器识别

- 判据:ACC_STATIC、描述符 `(Ljava/lang/String;)Ljava/lang/String;`、方法体含 `String.length()` 的调用;三条与名字无关——名可能是 demo 串或 i/I 排列,只能按形认。
- ACC_SYNTHETIC 常见但不入判据:8.x 的 `com/allatori/StackTrace` 非 synthetic 却是真解密器。
- 同签名的 ACC_NATIVE 解密器无方法体,字节码层不可还原:识别并报告,不改写其调用点。
- 一个 jar 内多解密器并存、各自独立 key,须逐个求值;按 owner 索引后多点复用。

## 形态 A:fast(常量双 key 反向 XOR)

1. **key 前奏**:纯 int 常量表达式(常量加载与整数运算),栈上残留 2 个 int 作为双 key;表达式里夹死常量对(`dup_x2+pop2` 整对丢弃)与 float junk(`fconst_*+pop`)。
2. **入口 guard**:`length()-1` 残留栈上,循环前 `iflt` 消费,空串直接短路。
3. **循环**:`i` 自 `len-1` 反向递减,双 key 交替,即 `plain[i] = cipher[i] ^ keys[(len-1-i) % 2]`。
4. **返回**:`new String(char[])`;全程不读调用方信息,密文可整体静态求值。

密文可含任意 UTF-16 序列,包括未配对代理项与 C0/C1 控制符。

## 形态 B:strong(常量 key + 调用方上下文)

1. **上下文**:`new RuntimeException().getStackTrace()[1]` 取调用方帧,`getMethodName() + getClassName()` 直接拼接、无分隔符。
2. **key 前奏**:与形态 A 同构,同样夹死常量与 junk。
3. **循环**:`plain[i] = cipher[i] ^ ctx.charAt(j) ^ key`,双 key 轮换;`j` 自 `ctxLen-1` 递减,越界回绕到 `ctxLen-1`。XOR 交换律使结合顺序不影响结果。
4. **还原必须在调用点做**:context 依赖调用方方法名与类名,同一密文在不同调用点解出不同明文;还原即原地替换 ldc 常量,不改布局。
