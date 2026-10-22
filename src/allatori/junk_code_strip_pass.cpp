#include "allatori/junk_code_strip_pass.hpp"

#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "jbc/core/opcode.hpp"
#include "jbc/ir/code_editor.hpp"
#include "jbc/ir/units.hpp"
#include "libca/log/log_macros.hpp"

#include "mjbase/pass/constant_folder.hpp"
#include "mjbase/pass/method_rewrite_util.hpp"
#include "mjbase/pass/redundant_load_val_eliminator.hpp"
#include "mjbase/pass/stack_operation.hpp"
#include "mjbase/spi/pass_pipeline.hpp"

namespace allatori {
namespace {

using jbc::core::Op;
using jbc::ir::CodeDom;
using jbc::ir::CodeEditor;
using jbc::ir::Insn;
using jbc::ir::InsnId;
using jbc::ir::LabelId;
using jbc::ir::LabelTarget;
namespace ir      = jbc::ir;
namespace util    = mjbase::pass::method_rewrite_util;

/// 字段键:owner | name | desc（0x01 分隔，字段名不含该字节）。
std::string fieldKey(std::string_view owner, std::string_view name, std::string_view desc)
{
    std::string k;
    k.reserve(owner.size() + name.size() + desc.size() + 2);
    k.append(owner);
    k.push_back('\x01');
    k.append(name);
    k.push_back('\x01');
    k.append(desc);
    return k;
}

bool isIcmp(Op op) noexcept
{
    switch (op) {
    case Op::IF_ICMPEQ:
    case Op::IF_ICMPNE:
    case Op::IF_ICMPLT:
    case Op::IF_ICMPGE:
    case Op::IF_ICMPGT:
    case Op::IF_ICMPLE:
        return true;
    default:
        return false;
    }
}

bool isIfZero(Op op) noexcept
{
    switch (op) {
    case Op::IFEQ:
    case Op::IFNE:
    case Op::IFLT:
    case Op::IFGE:
    case Op::IFGT:
    case Op::IFLE:
        return true;
    default:
        return false;
    }
}

/// if_icmpXX 求值:v1 <op> v2。
bool evalIcmp(Op op, ca::i32 v1, ca::i32 v2, bool& taken)
{
    switch (op) {
    case Op::IF_ICMPEQ: taken = v1 == v2; return true;
    case Op::IF_ICMPNE: taken = v1 != v2; return true;
    case Op::IF_ICMPLT: taken = v1 <  v2; return true;
    case Op::IF_ICMPGE: taken = v1 >= v2; return true;
    case Op::IF_ICMPGT: taken = v1 >  v2; return true;
    case Op::IF_ICMPLE: taken = v1 <= v2; return true;
    default: return false;
    }
}

/// ifXX 求值:v <op> 0。
bool evalIfZero(Op op, ca::i32 v, bool& taken)
{
    switch (op) {
    case Op::IFEQ: taken = v == 0; return true;
    case Op::IFNE: taken = v != 0; return true;
    case Op::IFLT: taken = v <  0; return true;
    case Op::IFGE: taken = v >= 0; return true;
    case Op::IFGT: taken = v >  0; return true;
    case Op::IFLE: taken = v <= 0; return true;
    default: return false;
    }
}

/// @brief 本类 static int 字段终值表。
///
/// 只接受「`<clinit>` 内恰好一次『int 常量装载; putstatic』」；任何其他写入
/// （非 clinit / 二次写 / 前驱非常量）毒化剔除。collectCodeUnits 安全批量
/// 升格（复用已 promote 的 CodeUnit，不重建，不碰当前方法的 scope.code）。
std::unordered_map<std::string, ca::i32> analyzeStaticIntFields(ir::ClassSession& session)
{
    std::unordered_map<std::string, ca::i32> values;
    std::unordered_set<std::string>          poisoned;
    const std::string_view                   thisName = session.backing().thisName();
    const ir::ClassUnit&                     unit     = session.unit();

    for (const ir::CodeVisit& visit : ir::collectCodeUnits(session)) {
        if (visit.kind != ir::CodeVisit::Kind::Ok) continue;
        const ir::MethodUnit& mu = unit.methods[visit.methodIdx];
        const bool            clinit = unit.symbols().str(mu.name) == "<clinit>";
        CodeDom&              dom    = visit.unit->dom;
        const std::vector<InsnId>& ids = dom.order();
        for (ca::usize i = 0; i < ids.size(); ++i) {
            const Insn* in = dom.peek(ids[i]);
            if (in == nullptr || in->op != Op::PUTSTATIC) continue;
            ir::ClassSession::MemberSem sem;
            if (!session.memberOf(*in, sem)) continue;
            if (sem.owner != thisName || sem.desc != "I") continue;
            const std::string key = fieldKey(sem.owner, sem.name, sem.desc);
            if (poisoned.count(key) != 0) continue;
            if (!clinit) {
                poisoned.insert(key);
                values.erase(key);
                continue;
            }
            if (values.count(key) != 0) {
                poisoned.insert(key);
                values.erase(key);
                continue;
            }
            ca::i32 v = 0;
            const Insn* prev = i > 0 ? dom.peek(ids[i - 1]) : nullptr;
            if (prev == nullptr || !util::intValueOf(session, *prev, v)) {
                poisoned.insert(key);
                continue;
            }
            values.emplace(key, v);
        }
    }
    return values;
}

/// @brief 邻接谓词改写（fixpoint）：命中字段终值表的比较静态求值。
///
/// 形态（全部要求邻接，无中间指令）：
///   - `getstatic f; <int常量>; if_icmpXX`（栈 [v][k] → v1=v, v2=k）
///   - `<int常量>; getstatic f; if_icmpXX`（栈 [k][v] → v1=k, v2=v）
///   - `getstatic f; ifXX` / `<int常量>; ifXX`（单操作数，对 0 比较）
/// 恒真 → if 原地改 GOTO（Branch2 同形），删除前缀；恒假 → 三/二指令
/// 全删。任一批内成员被存活引用/Boundary 锚定则本轮放弃（eraseBatch
/// 全有或全无），保守跳过。恒真且目标为方法末尾标签（End）不改写。
bool stripOpaquePredicates(mjbase::spi::MethodScope&                            scope,
                           const std::unordered_map<std::string, ca::i32>&     fields)
{
    ir::CodeDom&      dom    = scope.code.dom;
    ir::CodeEditor    editor(scope.code);
    const std::string_view thisName = scope.session.backing().thisName();

    // 取 getstatic 命中字段终值表的值；未命中返回 false。
    auto fieldValue = [&](const Insn& in, ca::i32& out) {
        if (in.op != Op::GETSTATIC) return false;
        ir::ClassSession::MemberSem sem;
        if (!scope.session.memberOf(in, sem)) return false;
        if (sem.owner != thisName || sem.desc != "I") return false;
        auto it = fields.find(fieldKey(sem.owner, sem.name, sem.desc));
        if (it == fields.end()) return false;
        out = it->second;
        return true;
    };

    // 恒真:if → GOTO（原地）,删前缀;失败回退 op。
    auto toGoto = [&](InsnId branchId, const std::vector<InsnId>& prefix) {
        auto gr = dom.get(branchId);
        if (gr.is_err()) return false;
        Insn*     keep  = gr.unwrap();
        const Op  oldOp = keep->op;
        keep->op        = Op::GOTO;
        if (editor.eraseBatch(prefix, CodeEditor::ErasePolicy::kRejectIfUsed).is_ok()) {
            return true;
        }
        keep->op = oldOp;
        return false;
    };

    bool changed = false;
    bool progress = true;
    int  rounds   = 0;
    const int maxRounds = static_cast<int>(dom.size()) + 8;
    while (progress && rounds++ < maxRounds) {
        progress = false;
        // 快照:erase 后洞位 peek 为 nullptr 自然跳过,邻接失效留待下一轮。
        const std::vector<InsnId> ids = dom.order();
        for (ca::usize i = 0; i < ids.size(); ++i) {
            const Insn* c = dom.peek(ids[i]);
            if (c == nullptr) continue;
            const bool icmp = isIcmp(c->op);
            if (!icmp && !isIfZero(c->op)) continue;

            const Insn* b = i > 0 ? dom.peek(ids[i - 1]) : nullptr;
            if (b == nullptr) continue;

            ca::i32 lhs = 0;
            ca::i32 rhs = 0;
            bool    ok  = false;
            std::vector<InsnId> prefix;

            if (icmp) {
                const Insn* a = i > 1 ? dom.peek(ids[i - 2]) : nullptr;
                if (a == nullptr) continue;
                ca::i32 va = 0;
                ca::i32 vb = 0;
                const bool aField = fieldValue(*a, va);
                const bool bField = fieldValue(*b, vb);
                if (aField && util::intValueOf(scope.session, *b, rhs)) {
                    lhs     = va;   // 栈 [v][k] → v1=v, v2=k
                    ok      = true;
                    prefix  = {ids[i - 2], ids[i - 1]};
                }
                else if (bField && util::intValueOf(scope.session, *a, lhs)) {
                    rhs     = vb;   // 栈 [k][v] → v1=k, v2=v
                    ok      = true;
                    prefix  = {ids[i - 2], ids[i - 1]};
                }
                else {
                    continue;
                }
            }
            else {
                ca::i32 vb = 0;
                if (fieldValue(*b, vb)) {
                    lhs = vb;       // v <op> 0
                    ok  = true;
                }
                else if (util::intValueOf(scope.session, *b, lhs)) {
                    ok = true;      // k <op> 0
                }
                else {
                    continue;
                }
                prefix = {ids[i - 1]};
            }

            bool taken = false;
            const bool evaluated =
                icmp ? evalIcmp(c->op, lhs, rhs, taken) : evalIfZero(c->op, lhs, taken);
            if (!evaluated) continue;

            if (taken) {
                // GOTO 不可指向方法末尾边界（End）——无处可去，跳过。
                auto target = dom.resolveLabel(c->target);
                if (target.is_err() || target.unwrap().isEnd()) continue;
                if (toGoto(ids[i], prefix)) {
                    progress = changed = true;
                }
            }
            else {
                std::vector<InsnId> kill = prefix;
                kill.push_back(ids[i]);
                // 保存分支目标 label:eraseBatch 不处理 label,删除分支后该
                // ControlFlow label 会悬空锚定在目标指令上,阻止后续 DCE 清除
                // 死段。importFrom 为每个分支创建独占 label,但重写后可能共享,
                // 销毁前扫描确认无其他存活指令引用。
                const LabelId targetLabel = c->target;
                if (editor.eraseBatch(kill, CodeEditor::ErasePolicy::kRejectIfUsed).is_ok()) {
                    bool shared = false;
                    for (const InsnId& uid : dom.order()) {
                        const Insn* u = dom.peek(uid);
                        if (u == nullptr) continue;
                        if (u->target == targetLabel) { shared = true; break; }
                        for (const LabelId& l : u->targets) {
                            if (l == targetLabel) { shared = true; break; }
                        }
                        if (shared) break;
                    }
                    if (!shared) (void)dom.destroyLabel(targetLabel);
                    progress = changed = true;
                }
            }
        }
    }
    return changed;
}

/// @brief 线性可达性死段清除。
///
/// 根 = 方法入口 + 全部异常表 handler 入口；边 = 分支/switch 目标 +
/// 顺序 fallthrough（GOTO/switch/return/athrow/ret 截断 fallthrough）。
/// 不可达且无标签锚定（labelsAt 为空）者批量删除；整批 StillUsed 时回退
/// 逐条 kRejectIfUsed（带锚成员保留）。
bool eraseUnreachableRuns(mjbase::spi::MethodScope& scope)
{
    ir::CodeDom& dom = scope.code.dom;
    const std::vector<InsnId>& ids = dom.order();
    if (ids.empty()) return false;

    struct IdHash
    {
        ca::usize operator()(const InsnId& x) const noexcept
        {
            return static_cast<ca::usize>(x.slot) * 0x9E3779B97F4A7C15ull
                   ^ static_cast<ca::usize>(x.owner) * 0x100000001B3ull
                   ^ static_cast<ca::usize>(x.gen);
        }
    };
    std::unordered_map<InsnId, ca::usize, IdHash> pos;
    pos.reserve(ids.size());
    for (ca::usize i = 0; i < ids.size(); ++i) pos.emplace(ids[i], i);

    std::vector<char>        reach(ids.size(), 0);
    std::vector<ca::usize>   work;
    auto                     mark = [&](InsnId id) {
        auto it = pos.find(id);
        if (it == pos.end() || reach[it->second]) return;
        reach[it->second] = 1;
        work.push_back(it->second);
    };
    auto markLabel = [&](LabelId lbl) {
        auto r = dom.resolveLabel(lbl);
        if (r.is_err()) return;
        const LabelTarget t = r.unwrap();
        if (t.kind == jbc::ir::LabelTargetKind::Instruction) mark(t.insn);
    };

    mark(ids[0]);
    for (const ir::CodeUnit::Exc& e : scope.code.exc) markLabel(e.handler);

    while (!work.empty()) {
        const ca::usize idx = work.back();
        work.pop_back();
        const Insn* in = dom.peek(ids[idx]);
        if (in == nullptr) continue;
        switch (in->op) {
        case Op::GOTO:
        case Op::GOTO_W:
        case Op::JSR:
            markLabel(in->target);
            break;
        case Op::IRETURN:
        case Op::LRETURN:
        case Op::FRETURN:
        case Op::DRETURN:
        case Op::ARETURN:
        case Op::RETURN:
        case Op::ATHROW:
        case Op::RET:
            break;
        case Op::TABLESWITCH:
        case Op::LOOKUPSWITCH:
            markLabel(in->target);
            for (const LabelId& l : in->targets) markLabel(l);
            break;
        default:
            if (isIfZero(in->op) || isIcmp(in->op)) {
                markLabel(in->target);
            }
            if (idx + 1 < ids.size()) mark(ids[idx + 1]);
            break;
        }
    }

    std::vector<InsnId> dead;
    for (ca::usize i = 0; i < ids.size(); ++i) {
        if (reach[i]) continue;
        if (!dom.labelsAt(ids[i]).empty()) continue;   // Boundary 锚定,保留
        dead.push_back(ids[i]);
    }
    if (dead.empty()) return false;

    ir::CodeEditor editor(scope.code);
    if (editor.eraseBatch(dead, CodeEditor::ErasePolicy::kRejectIfUsed).is_ok()) return true;
    // 回退逐条:带存活引用者拒绝,其余照删。
    bool changed = false;
    for (auto it = dead.rbegin(); it != dead.rend(); ++it) {
        if (editor.erase(*it, CodeEditor::ErasePolicy::kRejectIfUsed).is_ok()) changed = true;
    }
    return changed;
}

/// 内置件编排:CF → SOS → RLVE → CF（本地 AM,内置件不消费跨方法缓存）。
bool runBuiltinCleanup(mjbase::spi::MethodScope& scope)
{
    ca::str::Utf8StringArena            arena;
    mjbase::spi::MethodAnalysisManager  am(arena);
    mjbase::pass::ConstantFolder            folder;
    mjbase::pass::StackOperationSimplifier  stackOps;
    mjbase::pass::RedundantLoadValEliminator loadVal;

    bool modified = false;
    auto apply    = [&](auto& pass) {
        const mjbase::spi::PreservedAnalyses pa = pass.run(scope, am);
        am.invalidate(scope, pa);
        if (!pa.areAllPreserved()) modified = true;
    };
    apply(folder);
    apply(stackOps);
    apply(loadVal);
    apply(folder);
    return modified;
}

}   // namespace

mjbase::spi::PreservedAnalyses AllatoriJunkCodeStripPass::run(mjbase::spi::MethodScope&       scope,
                                                              mjbase::spi::MethodAnalysisManager& mam)
{
    (void)mam;
    bool modified = false;

    // 阶段一:折叠谓词侧未折叠常量表达式(1^3 → 2 等)。
    modified |= runBuiltinCleanup(scope);

    // 字段终值表按会话一次性分析;改写不写字段,fixpoint 内复用安全。
    const std::unordered_map<std::string, ca::i32> fields = analyzeStaticIntFields(scope.session);
    for (int round = 0; round < 8; ++round) {
        const bool stripped = stripOpaquePredicates(scope, fields);
        const bool dce      = eraseUnreachableRuns(scope);
        if (!stripped && !dce) break;
        modified = true;
    }

    // 阶段四:清除改写残渣。
    modified |= runBuiltinCleanup(scope);

    return modified ? mjbase::spi::PreservedAnalyses::none()
                    : mjbase::spi::PreservedAnalyses::all();
}

}   // namespace allatori
