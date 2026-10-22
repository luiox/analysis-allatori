#include "allatori/string_decrypt_pass.hpp"

#include <deque>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "jbc/core/class_file.hpp"
#include "jbc/core/opcode.hpp"
#include "jbc/core/writer.hpp"
#include "jbc/ir/code_editor.hpp"
#include "jbc/ir/units.hpp"
#include "jstr/conversion.hpp"
#include "jstr/mutf8_string.hpp"
#include "libca/str/utf16_string.hpp"
#include "libca/str/utf8_string.hpp"

#include "mjbase/model/resource_model.hpp"
#include "mjbase/pass/method_rewrite_util.hpp"

namespace allatori {
using ca::core::Err;
using ca::core::Ok;
using ca::core::Result;

namespace {

using jbc::core::Op;
using jbc::ir::ClassSession;
using jbc::ir::CodeDom;
using jbc::ir::CodeEditor;
using jbc::ir::CodeUnitRef;
using jbc::ir::Insn;
using jbc::ir::InsnId;

// JVM 访问标志（JVMS 4.1）。
constexpr ca::u32 kAccStatic    = 0x0008;
constexpr ca::u32 kAccNative    = 0x0100;
constexpr ca::u32 kAccSynthetic = 0x1000;

/// 解密器描述符（Allatori 9.x 固定形状）。
constexpr std::string_view kDecryptorDesc = "(Ljava/lang/String;)Ljava/lang/String;";

/// 解释器步数上限（防个别解密器内含超长循环体的病态展开）。
constexpr int kMaxSteps = 50000;

// ── 解释器值模型 ──

/// 解释器运行时值（tagged union）。引用类用 shared_ptr 表达 JVM 引用语义
/// （dup 复制句柄、StringBuffer 原地变更共享同一内容）。
struct Value
{
    enum class Kind : ca::u8 {
        Null,    ///< aconst_null
        Int,     ///< int / char（i2c 后仍为 Int，值在 0..0xFFFF）
        Float,   ///< float junk（fconst_*，只 pop 不解释）
        Str,     ///< java/lang/String（UTF-16 内容）
        Sb,      ///< StringBuffer / StringBuilder（可变 UTF-16 缓冲）
        Rt,      ///< RuntimeException 占位（getStackTrace 接收者）
        Ste,     ///< StackTraceElement（指向 frames 的下标）
        Frames,  ///< StackTraceElement[]（getStackTrace 产物）
        Arr,     ///< char[]（元素为 int，castore 存原始 int、caload 读 u16 截断）
        NewStr,  ///< new String 未初始化占位（String.<init>([C) 的接收者）
    };

    Kind kind = Kind::Null;
    ca::i32 i = 0;
    std::u16string s;   ///< Str / Sb 的 UTF-16 内容
    std::shared_ptr<std::u16string> sb;   ///< Sb 可变缓冲（dup 共享）
    std::shared_ptr<std::vector<ca::i32>> arr;   ///< Arr 元素
    ca::usize steIdx = 0;   ///< Ste → frames 下标
    std::shared_ptr<std::vector<std::pair<std::u16string, std::u16string>>> frames;
};

/// 解释失败原因（诊断用；调用方只区分「放弃本点」与「放弃整个解密器」）。
enum class InterpFail : ca::u8 {
    Ok,
    UnknownInsn,   ///< 解密器体含不支持指令 → 放弃该解密器全部调用点
    Runtime,       ///< 运行期异常（除零/越界/栈错位）→ 放弃本调用点
    BadResult,     ///< 返回值类型/明文非法 → 放弃本调用点
};

/// UTF-16 码元序列明文合法性（§7.4 兜底）：拒 NUL、拒未配对代理项、
/// 拒 C0/C1 控制符（`\t` `\n` `\r` 放行——验证语料含换行）。
bool plainUtf16Ok(const std::u16string& s)
{
    for (ca::usize i = 0; i < s.size(); ++i) {
        const ca::u16 c = s[i];
        if (c == 0) return false;
        if (c >= 0xD800 && c <= 0xDBFF) {
            if (i + 1 >= s.size()) return false;
            const ca::u16 n = s[i + 1];
            if (n < 0xDC00 || n > 0xDFFF) return false;
            ++i;
        }
        else if (c >= 0xDC00 && c <= 0xDFFF) {
            return false;   // 孤立低代理
        }
        else if (c < 0x20 && c != 0x09 && c != 0x0A && c != 0x0D) {
            return false;
        }
        else if (c >= 0x7F && c <= 0x9F) {
            return false;   // C1
        }
    }
    return true;
}

/// MUTF-8（CP 字节）→ UTF-16 码元序列（解释器 charAt/length 语义面）。
/// 路径：MUTF-8 → UTF-8 → Utf16String → code units。
bool cipherToUtf16(std::string_view mutf8, std::u16string& out)
{
    const jstr::MUtf8StringRef src(mutf8.data(), mutf8.size());
    const auto                 utf8Result = jstr::mutf8_to_utf8(src);
    if (utf8Result.is_err()) return false;
    try {
        const std::string& utf8 = utf8Result.unwrap();
        const ca::str::Utf16String u16 = ca::str::Utf16String::from_utf8_string(
            ca::str::Utf8StringRef::from_data(
                reinterpret_cast<const ca::u8*>(utf8.data()), utf8.size()));
        out.clear();
        out.reserve(u16.length());
        for (ca::usize i = 0; i < u16.length(); ++i) {
            out.push_back(static_cast<ca::u16>(u16.char_at(i).value));
        }
    }
    catch (...) {
        return false;
    }
    return true;
}

/// UTF-16 码元序列 → MUTF-8 字节（写回 internString 用；不可编码失败）。
bool utf16ToMutf8(const std::u16string& s, std::string& out)
{
    try {
        std::vector<ca::u16> units(s.begin(), s.end());
        const ca::str::Utf16String utf16(units.data(), units.size());
        const std::string          utf8 = utf16.to_utf8_string().ref().to_std_string();
        const auto                 mutf8 = jstr::utf8_to_mutf8(utf8);
        if (mutf8.is_err()) return false;
        out = mutf8.unwrap().bytes();
    }
    catch (...) {
        return false;
    }
    return true;
}

/// 内部名 → 点分名（StackTraceElement.getClassName 语义面）。
std::string toDotted(std::string_view internal)
{
    std::string out(internal);
    for (char& c : out) {
        if (c == '/') c = '.';
    }
    return out;
}

// ── 解密器记录 ──

struct DecryptorInfo
{
    std::string             owner;    ///< 类内部名
    std::string             name;
    std::string             desc;
    ca::usize               methodIdx = 0;
    std::shared_ptr<ClassSession> session;   ///< 所属会话（保活）
    CodeUnitRef             unit;            ///< promote 产物（解释用；不 lower 不写回）
    bool                    strong = false;  ///< 含 getStackTrace
    bool                    poisoned = false;///< 体含不支持指令，全部调用点放弃
};

/// 解密器表键：owner + '.' + name + desc。
std::string decryptorKey(std::string_view owner, std::string_view name, std::string_view desc)
{
    std::string key(owner);
    key.push_back('.');
    key.append(name);
    key.append(desc);
    return key;
}

/// 扫描解密器体是否含指定 owner.name 的 invoke（强形态探测用）。
bool bodyHasInvoke(const DecryptorInfo& d, std::string_view owner, std::string_view name)
{
    const std::vector<InsnId> ids = d.unit->dom.order();
    for (const InsnId id : ids) {
        const Insn* in = d.unit->dom.peek(id);
        if (in == nullptr) continue;
        if (in->op != Op::INVOKEVIRTUAL && in->op != Op::INVOKEINTERFACE &&
            in->op != Op::INVOKESPECIAL && in->op != Op::INVOKESTATIC)
        {
            continue;
        }
        ClassSession::MemberSem sem;
        if (!d.session->memberOf(*in, sem)) continue;
        if (sem.owner == owner && sem.name == name) return true;
    }
    return false;
}

/// 识别候选：方法骨架满足签名/访问位；有体再验证 String.length 并 promote。
/// 返回 nullptr 表示非解密器；native 匹配签名者记 warn 并返回占位（poisoned）。
DecryptorInfo* tryIdentifyDecryptor(std::deque<DecryptorInfo>& out,
                                    const std::shared_ptr<ClassSession>& session,
                                    ca::usize methodIdx)
{
    jbc::ir::MethodUnit& mu = session->unit().methods[methodIdx];
    const std::string_view    name =
        session->unit().symbols().str(mu.name);
    const std::string_view desc = session->unit().symbols().str(mu.desc);
    if (desc != kDecryptorDesc) return nullptr;
    if ((mu.access & kAccStatic) == 0) return nullptr;

    if ((mu.access & kAccNative) != 0 || !jbc::ir::hasCode(*session, methodIdx)) {
        CA_LOG_WARN(
            "[AllatoriStringDecrypt] native/无体解密器候选 {}.{}{} — 跳过并上报",
            std::string(session->backing().thisName()), name, desc);
        DecryptorInfo d;
        d.owner     = std::string(session->backing().thisName());
        d.name      = std::string(name);
        d.desc      = std::string(desc);
        d.methodIdx = methodIdx;
        d.session   = session;
        d.poisoned  = true;
        out.push_back(std::move(d));
        return &out.back();
    }

    auto promoted = jbc::ir::promoteMethod(*session, methodIdx);
    if (promoted.is_err()) return nullptr;

    DecryptorInfo d;
    d.owner     = std::string(session->backing().thisName());
    d.name      = std::string(name);
    d.desc      = std::string(desc);
    d.methodIdx = methodIdx;
    d.session   = session;
    d.unit      = std::move(promoted).unwrap();
    d.strong    = bodyHasInvoke(d, "java/lang/RuntimeException", "getStackTrace");
    if (!bodyHasInvoke(d, "java/lang/String", "length")) return nullptr;
    out.push_back(std::move(d));
    return &out.back();
}

// ── 字节码解释器 ──

struct InterpResult
{
    InterpFail fail = InterpFail::Ok;
    Value      value;   ///< fail == Ok 时有效（kind == Str）
};

/// 强形态上下文：frame[0]=Thread.getStackTrace（哑），frame[1]=调用方。
/// 调用方类名取点分 FQN（getClassName 语义），方法名取简单名。
void buildFakeFrames(Value& frames, std::string_view callerClassDotted,
                     std::string_view callerMethod)
{
    frames.kind   = Value::Kind::Frames;
    frames.frames = std::make_shared<
        std::vector<std::pair<std::u16string, std::u16string>>>();
    auto toU16 = [](std::string_view s) {
        std::u16string o;
        o.reserve(s.size());
        for (const char c : s) o.push_back(static_cast<ca::u16>(static_cast<ca::u8>(c)));
        return o;
    };
    frames.frames->emplace_back(toU16("java.lang.Thread"), toU16("getStackTrace"));
    frames.frames->emplace_back(toU16(callerClassDotted), toU16(callerMethod));
}

/// 解释一个解密器方法体：locals[0] = 密文（UTF-16）；strong 时构造假栈帧。
/// isIntermediate：本调用结果直接喂给链上下一层解密器（双层加密首层）——
/// 此时结果是中间态密文而非明文，跳过 §7.4 plainUtf16Ok 兜底；类型仍须为
/// String（堆栈语义不变），末端层照常全量校验。
InterpResult interpretDecryptor(const DecryptorInfo& d, std::string_view cipherUtf16Bytes,
                                bool /*unused*/, std::string_view callerClassDotted,
                                std::string_view callerMethod, bool isIntermediate)
{
    InterpResult out;
    CodeDom&     dom = d.unit->dom;
    const std::vector<InsnId> ids = dom.order();
    if (ids.empty()) {
        out.fail = InterpFail::Runtime;
        return out;
    }

    std::unordered_map<ca::u32, ca::usize> posOf;   // slot → order index
    for (ca::usize i = 0; i < ids.size(); ++i) posOf[ids[i].slot] = i;

    auto resolveIndex = [&](jbc::ir::LabelId label, ca::usize& outIdx) -> bool {
        const auto target = dom.resolveLabel(label);
        if (target.is_err()) return false;
        const jbc::ir::LabelTarget t = target.unwrap();
        if (t.isEnd()) {
            outIdx = ids.size();   // 落到方法末尾 = 越界退出
            return true;
        }
        const auto it = posOf.find(t.insn.slot);
        if (it == posOf.end()) return false;
        outIdx = it->second;
        return true;
    };

    std::vector<Value> stack;
    std::unordered_map<ca::i32, Value> locals;

    auto push = [&](Value v) { stack.push_back(std::move(v)); };
    auto pop = [&](Value& v) -> bool {
        if (stack.empty()) return false;
        v = std::move(stack.back());
        stack.pop_back();
        return true;
    };
    auto popInt = [&](ca::i32& outV) -> bool {
        Value v;
        if (!pop(v) || v.kind != Value::Kind::Int) return false;
        outV = v.i;
        return true;
    };
    auto asUtf16 = [](const Value& v, const std::u16string*& out) -> bool {
        if (v.kind == Value::Kind::Str) {
            out = &v.s;
            return true;
        }
        if (v.kind == Value::Kind::Sb && v.sb) {
            out = v.sb.get();
            return true;
        }
        return false;
    };

    // locals[0]：密文
    {
        Value cipher;
        cipher.kind = Value::Kind::Str;
        if (!cipherToUtf16(cipherUtf16Bytes, cipher.s)) {
            out.fail = InterpFail::Runtime;
            return out;
        }
        locals[0] = std::move(cipher);
    }

    Value result;
    bool  hasResult = false;
    ca::usize pc = 0;
    int  steps = 0;

    auto failUnknown = [&](const char* w) {
        (void)w;
        out.fail = InterpFail::UnknownInsn;
    };
    auto failRuntime = [&]() {
        out.fail = InterpFail::Runtime;
    };

    while (pc < ids.size()) {
        if (++steps > kMaxSteps) {
            failRuntime();
            return out;
        }
        const Insn* in = dom.peek(ids[pc]);
        if (in == nullptr) {
            failRuntime();
            return out;
        }
        ++pc;

        switch (in->op) {
        // ---- 局部变量 ----
        case Op::ILOAD: case Op::FLOAD: case Op::ALOAD:
        case Op::ILOAD_0: case Op::ILOAD_1: case Op::ILOAD_2: case Op::ILOAD_3:
        case Op::FLOAD_0: case Op::FLOAD_1: case Op::FLOAD_2: case Op::FLOAD_3:
        case Op::ALOAD_0: case Op::ALOAD_1: case Op::ALOAD_2: case Op::ALOAD_3: {
            ca::i32 idx = 0;
            switch (in->op) {
            case Op::ILOAD_0: case Op::FLOAD_0: case Op::ALOAD_0: idx = 0; break;
            case Op::ILOAD_1: case Op::FLOAD_1: case Op::ALOAD_1: idx = 1; break;
            case Op::ILOAD_2: case Op::FLOAD_2: case Op::ALOAD_2: idx = 2; break;
            case Op::ILOAD_3: case Op::FLOAD_3: case Op::ALOAD_3: idx = 3; break;
            default: idx = in->a; break;
            }
            const auto it = locals.find(idx);
            if (it == locals.end()) {
                failRuntime();
                return out;
            }
            push(it->second);
            break;
        }
        case Op::ISTORE: case Op::FSTORE: case Op::ASTORE:
        case Op::ISTORE_0: case Op::ISTORE_1: case Op::ISTORE_2: case Op::ISTORE_3:
        case Op::FSTORE_0: case Op::FSTORE_1: case Op::FSTORE_2: case Op::FSTORE_3:
        case Op::ASTORE_0: case Op::ASTORE_1: case Op::ASTORE_2: case Op::ASTORE_3: {
            ca::i32 idx = 0;
            switch (in->op) {
            case Op::ISTORE_0: case Op::FSTORE_0: case Op::ASTORE_0: idx = 0; break;
            case Op::ISTORE_1: case Op::FSTORE_1: case Op::ASTORE_1: idx = 1; break;
            case Op::ISTORE_2: case Op::FSTORE_2: case Op::ASTORE_2: idx = 2; break;
            case Op::ISTORE_3: case Op::FSTORE_3: case Op::ASTORE_3: idx = 3; break;
            default: idx = in->a; break;
            }
            Value v;
            if (!pop(v)) {
                failRuntime();
                return out;
            }
            locals[idx] = std::move(v);
            break;
        }

        // ---- 常量 ----
        case Op::ACONST_NULL: push(Value{}); break;
        case Op::ICONST_M1: case Op::ICONST_0: case Op::ICONST_1: case Op::ICONST_2:
        case Op::ICONST_3: case Op::ICONST_4: case Op::ICONST_5: {
            Value v;
            v.kind = Value::Kind::Int;
            v.i    = static_cast<ca::i32>(in->op) - static_cast<ca::i32>(Op::ICONST_0);
            if (in->op == Op::ICONST_M1) v.i = -1;
            push(v);
            break;
        }
        case Op::FCONST_0: case Op::FCONST_1: case Op::FCONST_2: {
            Value v;
            v.kind = Value::Kind::Float;
            push(v);
            break;
        }
        case Op::BIPUSH: case Op::SIPUSH: {
            Value v;
            v.kind = Value::Kind::Int;
            v.i    = in->a;
            push(v);
            break;
        }
        case Op::LDC: case Op::LDC_W: {
            ClassSession::ConstSem cs;
            if (!d.session->constOf(*in, cs)) {
                failRuntime();
                return out;
            }
            if (cs.kind == ClassSession::ConstSem::Kind::String) {
                Value v;
                v.kind = Value::Kind::Str;
                if (!cipherToUtf16(cs.str, v.s)) {
                    failRuntime();
                    return out;
                }
                push(v);
            }
            else if (cs.kind == ClassSession::ConstSem::Kind::Int) {
                Value v;
                v.kind = Value::Kind::Int;
                v.i    = static_cast<ca::i32>(cs.num);
                push(v);
            }
            else {
                failRuntime();
                return out;
            }
            break;
        }

        // ---- 整数算术 ----
        case Op::IAND: case Op::IOR: case Op::IXOR: case Op::IADD: case Op::ISUB:
        case Op::IMUL: case Op::IDIV: case Op::IREM: case Op::ISHL: case Op::ISHR:
        case Op::IUSHR: {
            ca::i32 b = 0;
            ca::i32 a = 0;
            if (!popInt(b) || !popInt(a)) {
                failRuntime();
                return out;
            }
            ca::i32 r = 0;
            switch (in->op) {
            case Op::IAND: r = a & b; break;
            case Op::IOR:  r = a | b; break;
            case Op::IXOR: r = a ^ b; break;
            case Op::IADD: r = a + b; break;
            case Op::ISUB: r = a - b; break;
            case Op::IMUL: r = a * b; break;
            case Op::IDIV:
                if (b == 0) {
                    failRuntime();
                    return out;
                }
                r = a / b;
                break;
            case Op::IREM:
                if (b == 0) {
                    failRuntime();
                    return out;
                }
                r = a % b;
                break;
            case Op::ISHL: r = a << (b & 31); break;
            case Op::ISHR: r = a >> (b & 31); break;
            case Op::IUSHR:
                r = static_cast<ca::i32>(static_cast<ca::u32>(a) >> (b & 31));
                break;
            default: break;
            }
            Value v;
            v.kind = Value::Kind::Int;
            v.i    = r;
            push(v);
            break;
        }
        case Op::INEG: {
            ca::i32 a = 0;
            if (!popInt(a)) {
                failRuntime();
                return out;
            }
            Value v;
            v.kind = Value::Kind::Int;
            v.i    = -a;
            push(v);
            break;
        }
        case Op::I2C: {
            ca::i32 a = 0;
            if (!popInt(a)) {
                failRuntime();
                return out;
            }
            Value v;
            v.kind = Value::Kind::Int;
            v.i    = static_cast<ca::i32>(static_cast<ca::u16>(a));
            push(v);
            break;
        }
        case Op::IINC: {
            const auto it = locals.find(in->a);
            if (it == locals.end() || it->second.kind != Value::Kind::Int) {
                failRuntime();
                return out;
            }
            it->second.i += in->b;
            break;
        }

        // ---- 栈操作 ----
        case Op::POP: {
            Value v;
            if (!pop(v)) {
                failRuntime();
                return out;
            }
            break;
        }
        case Op::POP2: {
            Value v;
            if (!pop(v) || !pop(v)) {
                failRuntime();
                return out;
            }
            break;
        }
        case Op::DUP: {
            if (stack.empty()) {
                failRuntime();
                return out;
            }
            push(stack.back());
            break;
        }
        case Op::DUP_X1: {
            Value v1;
            Value v2;
            if (!pop(v1) || !pop(v2)) {
                failRuntime();
                return out;
            }
            push(v1);
            push(v2);
            push(v1);
            break;
        }
        case Op::DUP_X2: {
            // 按值项数分派（long/double 本解密器子集不入栈）：
            // 深度 2 = JVMS form 1/2：… v2 v1 → … v1 v2 v1；
            // 深度 ≥3 = JVMS form 3：… v3 v2 v1 → … v1 v3 v2 v1。
            Value v1;
            Value v2;
            if (stack.size() < 2) {
                failRuntime();
                return out;
            }
            if (stack.size() == 2) {
                if (!pop(v1) || !pop(v2)) {
                    failRuntime();
                    return out;
                }
                push(v1);
                push(v2);
                push(v1);
                break;
            }
            Value v3;
            if (!pop(v1) || !pop(v2) || !pop(v3)) {
                failRuntime();
                return out;
            }
            push(v1);
            push(v3);
            push(v2);
            push(v1);
            break;
        }
        case Op::DUP2: {
            // Allatori 解密器中均为两个 cat-1 值形态。
            Value v1;
            Value v2;
            if (!pop(v1) || !pop(v2)) {
                failRuntime();
                return out;
            }
            push(v2);
            push(v1);
            push(v2);
            push(v1);
            break;
        }
        case Op::DUP2_X1: {
            Value v1;
            Value v2;
            Value v3;
            if (!pop(v1) || !pop(v2) || !pop(v3)) {
                failRuntime();
                return out;
            }
            push(v2);
            push(v1);
            push(v3);
            push(v2);
            push(v1);
            break;
        }
        case Op::DUP2_X2: {
            Value v1;
            Value v2;
            Value v3;
            Value v4;
            if (!pop(v1) || !pop(v2) || !pop(v3) || !pop(v4)) {
                failRuntime();
                return out;
            }
            push(v3);
            push(v4);
            push(v2);
            push(v1);
            push(v3);
            push(v4);
            break;
        }
        case Op::SWAP: {
            Value v1;
            Value v2;
            if (!pop(v1) || !pop(v2)) {
                failRuntime();
                return out;
            }
            push(v1);
            push(v2);
            break;
        }

        // ---- new / checkcast / newarray / 数组 ----
        case Op::NEW: {
            const std::string_view cls = d.session->classOf(*in);
            Value                 v;
            if (cls == "java/lang/StringBuffer" || cls == "java/lang/StringBuilder") {
                v.kind = Value::Kind::Sb;
                v.sb   = std::make_shared<std::u16string>();
            }
            else if (cls == "java/lang/RuntimeException") {
                v.kind = Value::Kind::Rt;
            }
            else if (cls == "java/lang/String") {
                v.kind = Value::Kind::NewStr;
            }
            else if (cls == "java/lang/StackTraceElement") {
                v.kind = Value::Kind::Ste;
            }
            else {
                failUnknown("new");
                return out;
            }
            push(v);
            break;
        }
        case Op::CHECKCAST:
            break;   // 保留栈顶引用原样
        case Op::NEWARRAY: {
            ca::i32 n = 0;
            if (!popInt(n) || n < 0) {
                failRuntime();
                return out;
            }
            Value v;
            v.kind = Value::Kind::Arr;
            v.arr  = std::make_shared<std::vector<ca::i32>>(
                static_cast<ca::usize>(n), 0);
            push(v);
            break;
        }
        case Op::AALOAD: {
            ca::i32 idx = 0;
            Value   arr;
            if (!popInt(idx)) {
                failRuntime();
                return out;
            }
            if (!pop(arr)) {
                failRuntime();
                return out;
            }
            if (arr.kind == Value::Kind::Frames) {
                // StackTraceElement[]：产出 Ste，指向对应帧。
                if (!arr.frames || idx < 0 ||
                    static_cast<ca::usize>(idx) >= arr.frames->size())
                {
                    failRuntime();
                    return out;
                }
                Value v;
                v.kind   = Value::Kind::Ste;
                v.frames = arr.frames;
                v.steIdx = static_cast<ca::usize>(idx);
                push(v);
                break;
            }
            if (arr.kind != Value::Kind::Arr || !arr.arr) {
                failRuntime();
                return out;
            }
            if (idx < 0 || static_cast<ca::usize>(idx) >= arr.arr->size()) {
                failRuntime();
                return out;
            }
            Value v;
            v.kind = Value::Kind::Int;
            v.i    = (*arr.arr)[static_cast<ca::usize>(idx)];
            push(v);
            break;
        }
        case Op::AASTORE: case Op::CASTORE: {
            Value val;
            ca::i32 idx = 0;
            Value   arr;
            if (!pop(val) || !popInt(idx) || !pop(arr) || arr.kind != Value::Kind::Arr ||
                !arr.arr)
            {
                failRuntime();
                return out;
            }
            if (idx < 0 || static_cast<ca::usize>(idx) >= arr.arr->size()) {
                failRuntime();
                return out;
            }
            if (val.kind != Value::Kind::Int) {
                failRuntime();
                return out;
            }
            (*arr.arr)[static_cast<ca::usize>(idx)] = val.i;
            break;
        }
        case Op::CALOAD: {
            ca::i32 idx = 0;
            Value   arr;
            if (!popInt(idx) || !pop(arr) || arr.kind != Value::Kind::Arr || !arr.arr) {
                failRuntime();
                return out;
            }
            if (idx < 0 || static_cast<ca::usize>(idx) >= arr.arr->size()) {
                failRuntime();
                return out;
            }
            Value v;
            v.kind = Value::Kind::Int;
            v.i    = static_cast<ca::i32>(
                static_cast<ca::u16>((*arr.arr)[static_cast<ca::usize>(idx)]));
            push(v);
            break;
        }

        // ---- 分支 ----
        case Op::GOTO: {
            ca::usize t = 0;
            if (!resolveIndex(in->target, t)) {
                failRuntime();
                return out;
            }
            pc = t;
            break;
        }
        case Op::IFEQ: case Op::IFNE: case Op::IFLT: case Op::IFGE: case Op::IFGT:
        case Op::IFLE: {
            ca::i32 c = 0;
            if (!popInt(c)) {
                failRuntime();
                return out;
            }
            bool ok = false;
            switch (in->op) {
            case Op::IFEQ: ok = c == 0; break;
            case Op::IFNE: ok = c != 0; break;
            case Op::IFLT: ok = c < 0; break;
            case Op::IFGE: ok = c >= 0; break;
            case Op::IFGT: ok = c > 0; break;
            case Op::IFLE: ok = c <= 0; break;
            default: break;
            }
            if (ok) {
                ca::usize t = 0;
                if (!resolveIndex(in->target, t)) {
                    failRuntime();
                    return out;
                }
                pc = t;
            }
            break;
        }
        case Op::IF_ICMPEQ: case Op::IF_ICMPNE: case Op::IF_ICMPLT: case Op::IF_ICMPGE:
        case Op::IF_ICMPGT: case Op::IF_ICMPLE: {
            ca::i32 b = 0;
            ca::i32 a = 0;
            if (!popInt(b) || !popInt(a)) {
                failRuntime();
                return out;
            }
            bool ok = false;
            switch (in->op) {
            case Op::IF_ICMPEQ: ok = a == b; break;
            case Op::IF_ICMPNE: ok = a != b; break;
            case Op::IF_ICMPLT: ok = a < b; break;
            case Op::IF_ICMPGE: ok = a >= b; break;
            case Op::IF_ICMPGT: ok = a > b; break;
            case Op::IF_ICMPLE: ok = a <= b; break;
            default: break;
            }
            if (ok) {
                ca::usize t = 0;
                if (!resolveIndex(in->target, t)) {
                    failRuntime();
                    return out;
                }
                pc = t;
            }
            break;
        }

        // ---- 返回 ----
        case Op::ARETURN: case Op::IRETURN: {
            if (!pop(result)) {
                failRuntime();
                return out;
            }
            hasResult = true;
            pc        = ids.size();
            break;
        }
        case Op::RETURN:
            hasResult = true;
            pc        = ids.size();
            break;

        // ---- invoke ----
        case Op::INVOKEVIRTUAL: case Op::INVOKEINTERFACE: case Op::INVOKESPECIAL: {
            ClassSession::MemberSem sem;
            if (!d.session->memberOf(*in, sem)) {
                failRuntime();
                return out;
            }
            const std::string_view o = sem.owner;
            const std::string_view n = sem.name;
            const std::string_view desc = sem.desc;

            auto countArgs = [&]() -> ca::i32 {
                // 描述符参数槽位数（全部 cat-1；解密器子集无 long/double 参）。
                const auto open  = desc.find('(');
                const auto close = desc.find(')');
                if (open == std::string_view::npos || close == std::string_view::npos ||
                    close < open)
                {
                    return -1;
                }
                ca::i32 count = 0;
                for (ca::usize i = open + 1; i < close;) {
                    const char c = desc[i];
                    if (c == 'L') {
                        const auto semi = desc.find(';', i);
                        if (semi == std::string_view::npos) return -1;
                        i = semi + 1;
                        ++count;
                    }
                    else if (c == '[') {
                        ++i;
                    }
                    else {
                        ++i;
                        ++count;
                    }
                }
                return count;
            };

            if (o == "java/lang/String" && n == "length" && desc == "()I") {
                Value s;
                if (!pop(s)) {
                    failRuntime();
                    return out;
                }
                const std::u16string* p = nullptr;
                if (!asUtf16(s, p)) {
                    failRuntime();
                    return out;
                }
                Value v;
                v.kind = Value::Kind::Int;
                v.i    = static_cast<ca::i32>(p->size());
                push(v);
                break;
            }
            if (o == "java/lang/String" && n == "charAt" && desc == "(I)C") {
                ca::i32 idx = 0;
                Value   s;
                if (!popInt(idx) || !pop(s)) {
                    failRuntime();
                    return out;
                }
                const std::u16string* p = nullptr;
                if (!asUtf16(s, p) || idx < 0 || static_cast<ca::usize>(idx) >= p->size()) {
                    failRuntime();
                    return out;
                }
                Value v;
                v.kind = Value::Kind::Int;
                v.i    = static_cast<ca::i32>((*p)[static_cast<ca::usize>(idx)]);
                push(v);
                break;
            }
            if (o == "java/lang/StringBuffer" || o == "java/lang/StringBuilder") {
                if (n == "<init>" && desc == "(Ljava/lang/String;)V") {
                    // 栈: …, sb, str；receiver 与栈上另一 dup 引用共享同一 sb。
                    Value str;
                    Value sbv;
                    if (!pop(str) || !pop(sbv) || sbv.kind != Value::Kind::Sb || !sbv.sb) {
                        failRuntime();
                        return out;
                    }
                    const std::u16string* p = nullptr;
                    if (!asUtf16(str, p)) {
                        failRuntime();
                        return out;
                    }
                    sbv.sb->assign(*p);
                    break;
                }
                if (n == "append") {
                    Value val;
                    Value sbv;
                    if (!pop(val) || !pop(sbv) || sbv.kind != Value::Kind::Sb || !sbv.sb) {
                        failRuntime();
                        return out;
                    }
                    const std::u16string* p = nullptr;
                    if (val.kind == Value::Kind::Str || val.kind == Value::Kind::Sb) {
                        if (!asUtf16(val, p)) {
                            failRuntime();
                            return out;
                        }
                        sbv.sb->append(*p);
                    }
                    else if (val.kind == Value::Kind::Int) {
                        // append(I)：按十进制拼接——Allatori 子集未观测到，
                        // 保守按字符码元拼接会错语义，直接失败更安全。
                        failUnknown("append(I)");
                        return out;
                    }
                    else {
                        failRuntime();
                        return out;
                    }
                    push(sbv);
                    break;
                }
                if (n == "insert" && desc.rfind("(ILjava/lang/String;)", 0) == 0) {
                    Value str;
                    ca::i32 idx = 0;
                    Value   sbv;
                    if (!pop(str) || !popInt(idx) || !pop(sbv) ||
                        sbv.kind != Value::Kind::Sb || !sbv.sb)
                    {
                        failRuntime();
                        return out;
                    }
                    const std::u16string* p = nullptr;
                    if (!asUtf16(str, p) || idx < 0 ||
                        static_cast<ca::usize>(idx) > sbv.sb->size())
                    {
                        failRuntime();
                        return out;
                    }
                    sbv.sb->insert(static_cast<ca::usize>(idx), *p);
                    push(sbv);
                    break;
                }
                if (n == "toString" && desc == "()Ljava/lang/String;") {
                    Value sbv;
                    if (!pop(sbv) || sbv.kind != Value::Kind::Sb || !sbv.sb) {
                        failRuntime();
                        return out;
                    }
                    Value v;
                    v.kind = Value::Kind::Str;
                    v.s    = *sbv.sb;
                    push(v);
                    break;
                }
                failUnknown("sb method");
                return out;
            }
            if (o == "java/lang/String" && n == "<init>" && desc.rfind("([C", 0) == 0) {
                // 栈: NewStr, char[]
                Value arr;
                Value obj;
                if (!pop(arr) || !pop(obj) || obj.kind != Value::Kind::NewStr ||
                    arr.kind != Value::Kind::Arr || !arr.arr)
                {
                    failRuntime();
                    return out;
                }
                Value v;
                v.kind = Value::Kind::Str;
                v.s.reserve(arr.arr->size());
                for (const ca::i32 e : *arr.arr) {
                    v.s.push_back(static_cast<ca::u16>(e));
                }
                push(v);
                break;
            }
            if (o == "java/lang/RuntimeException" && n == "getStackTrace" &&
                desc == "()[Ljava/lang/StackTraceElement;")
            {
                Value rt;
                if (!pop(rt)) {
                    failRuntime();
                    return out;
                }
                Value fr;
                buildFakeFrames(fr, callerClassDotted, callerMethod);
                push(fr);
                break;
            }
            if (o == "java/lang/StackTraceElement" && n == "getMethodName" &&
                desc == "()Ljava/lang/String;")
            {
                Value ste;
                if (!pop(ste) || ste.kind != Value::Kind::Ste || !ste.frames ||
                    ste.steIdx >= ste.frames->size())
                {
                    failRuntime();
                    return out;
                }
                Value v;
                v.kind = Value::Kind::Str;
                v.s    = (*ste.frames)[ste.steIdx].second;
                push(v);
                break;
            }
            if (o == "java/lang/StackTraceElement" && n == "getClassName" &&
                desc == "()Ljava/lang/String;")
            {
                Value ste;
                if (!pop(ste) || ste.kind != Value::Kind::Ste || !ste.frames ||
                    ste.steIdx >= ste.frames->size())
                {
                    failRuntime();
                    return out;
                }
                Value v;
                v.kind = Value::Kind::Str;
                v.s    = (*ste.frames)[ste.steIdx].first;
                push(v);
                break;
            }
            if (o == "java/lang/RuntimeException" && n == "<init>") {
                // 无状态：弹出接收者（+参数若 desc 非 ()V 由 countArgs 处理）。
                const ca::i32 argc = countArgs();
                if (argc < 0) {
                    failRuntime();
                    return out;
                }
                for (ca::i32 k = 0; k < argc; ++k) {
                    Value tmp;
                    if (!pop(tmp)) {
                        failRuntime();
                        return out;
                    }
                }
                Value obj;
                if (!pop(obj)) {
                    failRuntime();
                    return out;
                }
                break;
            }
            failUnknown("invoke");
            return out;
        }
        case Op::INVOKESTATIC: {
            ClassSession::MemberSem sem;
            if (!d.session->memberOf(*in, sem)) {
                failRuntime();
                return out;
            }
            if (sem.owner == "java/lang/String" && sem.name == "valueOf") {
                Value v;
                if (!pop(v)) {
                    failRuntime();
                    return out;
                }
                Value s;
                s.kind = Value::Kind::Str;
                if (v.kind == Value::Kind::Int) {
                    // valueOf(I)：十进制——Allatori 子集未观测，fail-loud。
                    failUnknown("valueOf(I)");
                    return out;
                }
                const std::u16string* p = nullptr;
                if (!asUtf16(v, p)) {
                    failRuntime();
                    return out;
                }
                s.s = *p;
                push(s);
                break;
            }
            failUnknown("invokestatic");
            return out;
        }

        // ---- 字段/监控/其余：不支持 ----
        default:
            failUnknown(jbc::core::mnemonicOf(in->op));
            return out;
        }
    }

    if (!hasResult) {
        out.fail = InterpFail::Runtime;
        return out;
    }
    if (result.kind != Value::Kind::Str) {
        out.fail = InterpFail::BadResult;
        return out;
    }
    if (!isIntermediate && !plainUtf16Ok(result.s)) {
        out.fail = InterpFail::BadResult;
        return out;
    }
    out.value = std::move(result);
    return out;
}

// ── 装载与调用点改写 ──

struct LoadedClass
{
    std::string                    name;   ///< 类内部名
    mjbase::model::ClassResource*  resource = nullptr;
    std::shared_ptr<ClassSession>  session;
    std::string                    uri;
    std::vector<ca::usize>         dirtyMethods;   ///< 已改写的逻辑下标
};

bool loadClass(mjbase::model::ClassResource& resource, LoadedClass& out)
{
    const auto& bytes = resource.get();
    if (bytes.empty()) return false;
    auto sessionResult = jbc::ir::makeSessionFromBytes(jbc::core::ByteView(bytes));
    if (sessionResult.is_err()) return false;
    out.session = std::move(sessionResult).unwrap();
    out.name.assign(out.session->backing().thisName());
    if (out.name.empty()) return false;
    out.resource = &resource;
    out.uri      = resource.getLocation().to_std_string();
    return true;
}

/// 单方法内扫描并改写全部可解调用点。返回本方法改写次数。
/// strongCtx 仅在解密器 strong 时使用（调用方简单名 + 点分类名）。
ca::usize rewriteCallSitesInMethod(LoadedClass& loaded, ca::usize methodIdx,
                                   const std::unordered_map<std::string, DecryptorInfo*>& table,
                                   std::string_view callerMethod)
{
    ClassSession&        session = *loaded.session;
    jbc::ir::MethodUnit& mu = session.unit().methods[methodIdx];
    const std::string_view     name = session.unit().symbols().str(mu.name);
    const std::string_view     desc = session.unit().symbols().str(mu.desc);
    (void)desc;

    // 解密器自身不改写（也不 promote 其他无体方法）。
    for (const auto& [key, d] : table) {
        if (d->session.get() == &session && d->methodIdx == methodIdx) return 0;
    }

    if (!jbc::ir::hasCode(session, methodIdx)) return 0;
    auto promoted = jbc::ir::promoteMethod(session, methodIdx);
    if (promoted.is_err()) return 0;
    CodeUnitRef unit = std::move(promoted).unwrap();

    CodeDom&   dom    = unit->dom;
    CodeEditor editor(*unit);

    const std::string dotted = toDotted(session.backing().thisName());
    ca::usize         rewritten = 0;
    bool              progress  = true;
    int               rounds    = 0;
    // 每轮至多重写一处（erase 使 ids 快照失效，须重扫），故轮数上界取
    // 本方法指令数：成功轮严格减少指令数，无成功轮 progress=false 自然退出。
    const int maxRounds = static_cast<int>(dom.order().size()) + 8;
    while (progress && rounds++ < maxRounds) {
        progress = false;
        // 每轮重新取序：erase 改变序列。
        const std::vector<InsnId> ids = dom.order();
        for (ca::usize i = 0; i + 1 < ids.size(); ++i) {
            const Insn* ldcIn = dom.peek(ids[i]);
            const Insn* invIn = dom.peek(ids[i + 1]);
            if (ldcIn == nullptr || invIn == nullptr) continue;
            if (invIn->op != Op::INVOKESTATIC) continue;
            if (ldcIn->op != Op::LDC && ldcIn->op != Op::LDC_W) continue;

            ClassSession::ConstSem cs;
            if (!session.constOf(*ldcIn, cs) ||
                cs.kind != ClassSession::ConstSem::Kind::String)
            {
                continue;
            }

            ClassSession::MemberSem sem;
            if (!session.memberOf(*invIn, sem)) continue;
            const auto it = table.find(decryptorKey(sem.owner, sem.name, sem.desc));
            if (it == table.end()) continue;
            DecryptorInfo* d = it->second;
            if (d->poisoned) continue;

            // 标签守卫：invokestatic 前置边界有锚定标签 → 跳过。
            if (mjbase::pass::method_rewrite_util::labelsAnchorAt(dom, ids[i + 1])) {
                continue;
            }

            // 链首判定：本调用结果直接喂给紧随其后的解密器调用（ldc;A;B 双层
            // 加密）→ A 的输出是中间态密文（常含 C0 控制符），免 §7.4 兜底；
            // B 层照常全量校验。非相邻（有其它指令隔断）保守按末端层处理。
            bool isIntermediate = false;
            if (i + 2 < ids.size()) {
                const Insn* nxtIn = dom.peek(ids[i + 2]);
                if (nxtIn != nullptr && nxtIn->op == Op::INVOKESTATIC) {
                    ClassSession::MemberSem nxtSem;
                    if (session.memberOf(*nxtIn, nxtSem) &&
                        table.find(decryptorKey(nxtSem.owner, nxtSem.name, nxtSem.desc)) !=
                            table.end())
                    {
                        isIntermediate = true;
                    }
                }
            }

            // 解释求值。
            const std::string_view callerCls = d->strong ? std::string_view(dotted) : std::string_view{};
            const std::string_view callerMtd = d->strong ? name : std::string_view{};
            InterpResult r =
                interpretDecryptor(*d, cs.str, d->strong, callerCls, callerMtd, isIntermediate);
            if (r.fail == InterpFail::UnknownInsn) {
                d->poisoned = true;
                CA_LOG_WARN(
                    "[AllatoriStringDecrypt] 解密器 {}.{}{} 含不支持指令，全部调用点放弃",
                    d->owner, d->name, d->desc);
                continue;
            }
            if (r.fail != InterpFail::Ok) {
                continue;
            }

            std::string plainMutf8;
            if (!utf16ToMutf8(r.value.s, plainMutf8)) {
                continue;
            }

            // 改写：setString(ldc) + erase(invokestatic)。
            Insn* ldcMut = dom.get(ids[i]).unwrap();
            if (!session.setString(*ldcMut, plainMutf8)) continue;
            if (editor.erase(ids[i + 1], CodeEditor::ErasePolicy::kRejectIfUsed).is_err()) {
                // erase 失败（异常表边界等）：ldc 已改明文但 invoke 仍在——
                // 栈效应破坏。setString 回滚不可行（CP 只追加），整方法放弃
                // 后续改写并告警；已改点由 fixpoint 再扫时 invoke 仍在，
                // 会再次解释——明文喂回解密器可能得不同结果，故直接 break
                // 本方法（保守：不再动该方法）。
                CA_LOG_WARN(
                    "[AllatoriStringDecrypt] erase 失败 {}.{}:{} @ slot {} — 放弃该方法剩余改写",
                    loaded.name, std::string(name), std::string(desc), ids[i + 1].slot);
                ++rewritten;
                return rewritten;
            }
            ++rewritten;
            progress = true;
            // ids 快照已失效，break 重扫。
            break;
        }
    }
    if (rewritten > 0) loaded.dirtyMethods.push_back(methodIdx);
    return rewritten;
}

}   // namespace

mjbase::spi::PreservedAnalyses AllatoriStringDecryptPass::run(
    mjbase::model::ResourceContainer& container, mjbase::spi::GlobalAnalysisManager& am)
{
    (void)am;

    // 阶段零：装载全部 class。
    std::vector<LoadedClass> loaded;
    for (auto& [uri, resource] : container.getResources()) {
        (void)uri;
        if (!resource || !ca::core::tag_cast::isa<mjbase::model::ClassResource>(resource.get())) {
            continue;
        }
        auto* cls = ca::core::tag_cast::cast<mjbase::model::ClassResource>(resource.get());
        LoadedClass entry;
        if (loadClass(*cls, entry)) loaded.push_back(std::move(entry));
    }
    if (loaded.empty()) return mjbase::spi::PreservedAnalyses::all();

    // 阶段一：识别解密器。用 deque：tryIdentifyDecryptor 返回 &out.back()
    // 指针存入 table，deque push_back 不使已有元素指针失效。
    std::deque<DecryptorInfo>                              decryptors;
    std::unordered_map<std::string, DecryptorInfo*>       table;
    for (LoadedClass& entry : loaded) {
        const ca::usize n = entry.session->unit().methods.size();
        for (ca::usize i = 0; i < n; ++i) {
            DecryptorInfo* d = tryIdentifyDecryptor(decryptors, entry.session, i);
            if (d == nullptr || d->poisoned) continue;
            table.emplace(decryptorKey(d->owner, d->name, d->desc), d);
        }
    }
    if (table.empty()) return mjbase::spi::PreservedAnalyses::all();

    // 阶段二：调用点扫描。链式连调由 rewriteCallSitesInMethod 内层
    // while-fixpoint 收口（promoteMethod 幂等=重建，外层不可重 promote）。
    // decryptors vector 在识别后不再 push_back（table 指针稳定）。
    ca::usize total = 0;
    for (LoadedClass& entry : loaded) {
        const ca::usize n = entry.session->unit().methods.size();
        for (ca::usize i = 0; i < n; ++i) {
            jbc::ir::MethodUnit&  mu    = entry.session->unit().methods[i];
            const std::string_view mname = entry.session->unit().symbols().str(mu.name);
            total += rewriteCallSitesInMethod(entry, i, table, mname);
        }
    }
    if (total == 0) return mjbase::spi::PreservedAnalyses::all();

    // 阶段三：lower 改写方法 + writeClass + replaceResource。
    for (LoadedClass& entry : loaded) {
        if (entry.dirtyMethods.empty()) continue;
        bool ok = true;
        for (const ca::usize i : entry.dirtyMethods) {
            const auto lowered = jbc::ir::lowerMethod(*entry.session, i);
            if (lowered.is_err()) {
                CA_LOG_WARN("[AllatoriStringDecrypt] lowerMethod 失败 {} method {} — 类保持原样",
                            entry.name, i);
                ok = false;
                break;
            }
        }
        if (!ok) continue;
        auto written = jbc::core::writeClass(entry.session->backing());
        if (written.is_err()) {
            throw std::runtime_error(std::string("AllatoriStringDecryptPass: write failed for '") +
                                     entry.name + "'");
        }
        container.replaceResource(
            entry.uri, std::make_unique<mjbase::model::ClassResource>(entry.uri,
                                                                      std::move(written).unwrap()));
    }

    return mjbase::spi::PreservedAnalyses::none();
}

Result<void, std::string> registerAll(mjbase::spi::PassNameRegistry& reg)
{
    if (Result<void, mjbase::spi::RegistryError> r = reg.registerGlobalPass(
            "allatori.StringDecrypt",
            [] { return std::make_unique<AllatoriStringDecryptPass>(); },
            "Fold Allatori string-decrypt call sites (fast XOR / strong stack-trace"
            " context) into plaintext ldc via an inline bytecode interpreter.");
        r.is_err()) {
        return Err(std::string("allatori.StringDecrypt"));
    }
    return Ok();
}

}   // namespace
