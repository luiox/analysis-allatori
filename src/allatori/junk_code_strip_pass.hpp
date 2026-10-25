#pragma once

#include "mjbase/spi/pass_pipeline.hpp"

namespace allatori {

/// @brief Allatori 死代码/opaque 注入剥离:恒假分支求值 + 死段清除,并编排
///        mjbase 内置清理件(常量折叠 / 栈窗化简 / 冗余装载删除)清偿
///        doc/junk-code.md 三形态
///
/// 三形态清偿路径(9.x 官方 demo jar 实测,见 doc/junk-code.md):
///   - 死常量块(`sipush×4 + pop2×2` / `iconst_1 dup pop2` / float junk):
///     RedundantLoadValEliminator + StackOperationSimplifier;
///   - 未折叠常量表达式(`bipush -8; ineg; ineg` / `sipush 4369; sipush 8738;
///     iand`):ConstantFolder(内置件);
///   - opaque 谓词与死分支(`if (obf3.false == (1 ^ 3))` /
///     `while (false)`):本 pass 核心——静态字段终值分析 + 邻接指令模式
///     匹配改写 + 不可达 run 清除。
///
/// @par opaque 谓词核心(本 pass 独有)
///
/// 阶段一·字段终值分析:扫描会话内全部方法(collectCodeUnits 安全批量升格,
/// 复用已 promote 的 CodeUnit 不重建),只接受「本类 static int 字段、仅在
/// `<clinit>` 内恰好一次『常量装载; putstatic』写入」;任何其他写入(非
/// clinit / 二次写 / 非常量)一律毒化剔除——保守求准,不猜。
///
/// 阶段二·谓词改写(fixpoint):邻接三指令模式
/// `getstatic f; <int常量>; if_icmpXX`(及常量在前的逆序、单操作数
/// `getstatic f; ifXX` / `<int常量>; ifXX` 变体)在字段命中终值表时静态
/// 求值:恒真 → 条件跳转原地改写为 GOTO(同 Branch2 形状,目标字段不变),
/// 随后删除 getstatic/常量两指令;恒假 → 连同条件跳转一起批量删除
/// (eraseBatch 全有或全无:任一成员被 Branch 引用或被 Boundary 标签锚定
/// 则本轮放弃该模式,保守跳过)。
///
/// 阶段三·死段清除:线性可达性标记(方法入口为根,分支/switch 目标 +
/// 顺序 fallthrough,return/athrow 截断;异常表 handler 入口恒为根),
/// 不可达且无标签锚定的指令批量删除;个别 StillUsed 回退逐条
/// kRejectIfUsed(带锚成员保留,不强迁边界)。
///
/// 阶段四·内置件编排:ConstantFolder → StackOperationSimplifier →
/// RedundantLoadValEliminator → ConstantFolder 清除改写残渣(本地
/// AnalysisManager,内置件不消费跨方法缓存)。四阶段整体 fixpoint 外层
/// 再包一层:谓词侧常量表达式先由内置件折叠成字面量,谓词改写产生的
/// 新常量链再由内置件二次折叠。
///
/// @par 边界(保守不追)
///
/// - 字段终值只看本类:跨类 opaque 字段(其他类的 static int)不做容器级
///   分析——Allatori 9.x 观测形态为同类字段;
/// - 字段类型限定 `I`:比较语境下的 boolean/byte 载体不入表(v1);
/// - 分支目标为方法末尾标签(End)的恒真分支不改写(GOTO 无处可去,
///   fallthrough 语义即原语义,直接跳过);
/// - 嵌套/交错的非邻接模式不追栈模拟:Allatori 注入形态观测为邻接序列。
///
/// 写回:由方法管线统一驱动 lower(本 pass 只改 CodeUnit)。
///
/// @par 标签
/// - `scope:method`
/// - `action:eliminate`
/// - `stability:opt-in`
class AllatoriJunkCodeStripPass : public mjbase::spi::MethodPass
{
public:
    mjbase::spi::PreservedAnalyses run(mjbase::spi::MethodScope&       scope,
                                       mjbase::spi::MethodAnalysisManager& mam) override;
};

}   // namespace allatori
