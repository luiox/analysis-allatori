#pragma once

#include <string>

#include "mjbase/model/resource_container.hpp"
#include "mjbase/spi/pass_name_registry.hpp"
#include "mjbase/spi/pass_pipeline.hpp"

namespace allatori {

/// @brief Allatori 通用静态字符串解密：识别合成 `(String)String` 解密器，用
///        内嵌字节码解释器求值全部 `ldc cipher; invokestatic decryptor` 调用点，
///        把调用点折叠为单条 `ldc plain`（解密器体本身不改写）。
///
/// 识别判据（对齐 Allatori 9.x 可观测面，不依赖名字）：
///   - 描述符 `(Ljava/lang/String;)Ljava/lang/String;`；
///   - `ACC_STATIC`（Allatori 通常另带 `ACC_SYNTHETIC`，但判据不强依赖：
///     8.x 样本存在非 synthetic 的真解密器 `com/allatori/StackTrace`）；
///   - 带 Code 且体内含 `java/lang/String.length ()I` 的 invokevirtual/invokeinterface；
///   - 体内含 `java/lang/RuntimeException.getStackTrace` 的形为 strong（可用
///     调用方 上下文），否则为 weak（仅用密文字节）。
///   - `ACC_NATIVE` 无体：跳过并 CA_LOG_WARN 上报（不静默）。
///
/// 调用点模式：序相邻 `ldc <String>; invokestatic <decryptor>`。守卫：
///   - invokestatic 前置边界有存活标签锚定（分支目标/异常表/调试边界）→
///     跳过该点（对齐旧栈 LabelNode 阻断相邻匹配）；
///   - ldc 不是 String 常量 / 解密器表未命中 → 不参与。
///
/// 改写：`setString(ldc, plain)` + `erase(invokestatic)`（kRejectIfUsed）。
/// 栈效应等价（前后净推 1 个 String，类型同为 String），maxStack 不变。
/// 链式连调（strong 产物喂 weak）经 fixpoint 循环重复扫描改写收口。
///
/// 解释器：覆盖解密器惯用指令子集（常量/局部变量/栈操作/整数算术/i2c/
/// String 与 StringBuffer 家族/char[]/分支/getStackTrace 上下文）；
/// 未知指令 fail-loud（该解密器全部调用点放弃）。明文合法性兜底：
/// 拒 NUL、拒未配对代理项、拒 C0/C1 控制符（`\t` `\n` `\r` 除外）。
///
/// 写回：改写后的类 lowerMethod → writeClass → replaceResource（同 URI）。
///
/// @par 标签
/// - `scope:global`
/// - `action:rewrite`
/// - `stability:opt-in`
class AllatoriStringDecryptPass : public mjbase::spi::GlobalPass
{
public:
    mjbase::spi::PreservedAnalyses run(mjbase::model::ResourceContainer&     container,
                                       mjbase::spi::GlobalAnalysisManager& am) override;
};

/// @brief 把本家族全部 pass 以 "allatori." 前缀名挂进给定注册表；注册面
///        拒绝时 Err 携带被拒 pass 名（pack 层映射为 RegistrationFailed）。
ca::core::Result<void, std::string> registerAll(mjbase::spi::PassNameRegistry& reg);

}   // namespace allatori
