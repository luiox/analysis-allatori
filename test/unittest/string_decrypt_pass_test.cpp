/// AllatoriStringDecryptPass 单测：夹具构造最小解密器（static+synthetic
/// (Ljava/lang/String;)Ljava/lang/String; + 体内含 String.length invokevirtual），
/// 断言调用点改写 / native 跳过 / 标签守卫跳过 / 链式 fixpoint / 非法明文拒写。
#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "jbc/core/class_file.hpp"
#include "jbc/core/insn_codec.hpp"
#include "jbc/core/opcode.hpp"
#include "jbc/core/reader.hpp"
#include "jbc/ir/units.hpp"
#include "libca/core/tag_cast.hpp"

#include "mjbase/model/resource_helper.hpp"
#include "mjbase/model/resource_model.hpp"
#include "allatori/pack.hpp"
#include "allatori/string_decrypt_pass.hpp"
#include "mjbase/plugin/pack.hpp"
#include "mjbase/spi/pass_name_registry.hpp"
#include "mjbase/spi/analysis_manager.hpp"
#include "mjbase/spi/preserved_analyses.hpp"
#include "shared/structural_pass_util.hpp"

using namespace mjbase::test;

namespace {

constexpr ca::u16 kAccPublic    = 0x0001;
constexpr ca::u16 kAccStatic    = 0x0008;
constexpr ca::u16 kAccNative    = 0x0100;
constexpr ca::u16 kAccSynthetic = 0x1000;

/// 解密器方法 access：static | synthetic = 0x1008。
constexpr ca::u16 kDecryptorAccess = static_cast<ca::u16>(kAccStatic | kAccSynthetic);

/// 最小可识别解密器体：aload_0; invokevirtual String.length; pop; ldc <result>; areturn。
/// length 调用仅为识别判据，结果始终为固定明文。
Bytes buildIdentityDecryptorBody(FixtureBuilder& builder, std::string_view resultPlain)
{
    const ca::u16 sref =
        builder.methodRef("java/lang/String", "length", "()I");
    const ca::u16 sconst = builder.strConst(resultPlain);
    return {
        0x2A,                                              // ALOAD_0
        0xB6, static_cast<ca::u8>(sref >> 8), static_cast<ca::u8>(sref),   // INVOKEVIRTUAL String.length
        0x57,                                              // POP
        0x12, static_cast<ca::u8>(sconst),                 // LDC resultPlain
        0xB0,                                              // ARETURN
    };
}

/// 密码解密器类：仅含 decryptor 方法。
Bytes buildDecryptorClass(std::string_view className, std::string_view resultPlain)
{
    FixtureBuilder builder(className);
    FixtureMethod  m;
    m.name       = "a";
    m.desc       = "(Ljava/lang/String;)Ljava/lang/String;";
    m.access     = kDecryptorAccess;
    m.maxStack   = 2;
    m.maxLocals  = 1;
    m.code       = buildIdentityDecryptorBody(builder, resultPlain);
    builder.addMethod(m);
    return builder.assemble();
}

/// 调用方类：single 方法 `call()Ljava/lang/String;` 内含
/// `LDC cipher; INVOKESTATIC decryptor.a; ARETURN`。
Bytes buildCallerClass(std::string_view className, std::string_view decryptorOwner,
                       std::string_view cipher, bool withLabelGuard = false)
{
    FixtureBuilder builder(className);
    const ca::u16  dref =
        builder.methodRef(decryptorOwner, "a", "(Ljava/lang/String;)Ljava/lang/String;");
    const ca::u16 cconst = builder.strConst(cipher);

    Bytes code;
    if (withLabelGuard) {
        // ICONST_0; IFNE L; L: LDC cipher; INVOKESTATIC …; ARETURN
        // L 为分支目标 → 有锚定标签 → invokestatic 前置边界守卫命中 → 跳过。
        code = {
            0x03,                                              // ICONST_0
            0x9A, 0x00, 0x04,                                  // IFNE L (+4 → 指向 LDC)
            0x12, static_cast<ca::u8>(cconst),                 // L: LDC cipher
            0xB8, static_cast<ca::u8>(dref >> 8), static_cast<ca::u8>(dref),  // INVOKESTATIC
            0xB0,                                              // ARETURN
        };
    }
    else {
        code = {
            0x12, static_cast<ca::u8>(cconst),                 // LDC cipher
            0xB8, static_cast<ca::u8>(dref >> 8), static_cast<ca::u8>(dref),  // INVOKESTATIC
            0xB0,                                              // ARETURN
        };
    }

    FixtureMethod call;
    call.name      = "call";
    call.desc      = "()Ljava/lang/String;";
    call.access    = static_cast<ca::u16>(kAccPublic | kAccStatic);
    call.maxStack  = 1;
    call.maxLocals = 0;
    call.code      = std::move(code);
    builder.addMethod(call);
    return builder.assemble();
}

/// 链式夹具：Strong(返回 identity 结果 "Hello") + Weak(返回 "World")，
/// 调用方 `LDC cipher; invokestatic Strong; invokestatic Weak; ARETURN`。
Bytes buildStrongDecryptor()
{
    FixtureBuilder builder("pkg/Strong");
    FixtureMethod  m;
    m.name      = "a";
    m.desc      = "(Ljava/lang/String;)Ljava/lang/String;";
    m.access    = kDecryptorAccess;
    m.maxStack  = 2;
    m.maxLocals = 1;
    m.code      = buildIdentityDecryptorBody(builder, "Hello");
    builder.addMethod(m);
    return builder.assemble();
}

Bytes buildWeakDecryptor()
{
    FixtureBuilder builder("pkg/Weak");
    FixtureMethod  m;
    m.name      = "a";
    m.desc      = "(Ljava/lang/String;)Ljava/lang/String;";
    m.access    = kDecryptorAccess;
    m.maxStack  = 2;
    m.maxLocals = 1;
    m.code      = buildIdentityDecryptorBody(builder, "World");
    builder.addMethod(m);
    return builder.assemble();
}

/// 链式调用方：LDC "seed"; invokestatic Strong.a; invokestatic Weak.a; ARETURN。
Bytes buildChainCaller()
{
    FixtureBuilder builder("pkg/Caller");
    const ca::u16  sref =
        builder.methodRef("pkg/Strong", "a", "(Ljava/lang/String;)Ljava/lang/String;");
    const ca::u16 wref =
        builder.methodRef("pkg/Weak", "a", "(Ljava/lang/String;)Ljava/lang/String;");
    const ca::u16 seed = builder.strConst("seed");

    FixtureMethod call;
    call.name      = "call";
    call.desc      = "()Ljava/lang/String;";
    call.access    = static_cast<ca::u16>(kAccPublic | kAccStatic);
    call.maxStack  = 1;
    call.maxLocals = 0;
    call.code      = {
        0x12, static_cast<ca::u8>(seed),                                       // LDC seed
        0xB8, static_cast<ca::u8>(sref >> 8), static_cast<ca::u8>(sref),        // INVOKESTATIC Strong.a
        0xB8, static_cast<ca::u8>(wref >> 8), static_cast<ca::u8>(wref),        // INVOKESTATIC Weak.a
        0xB0,                                                                  // ARETURN
    };
    builder.addMethod(call);
    return builder.assemble();
}

/// 非法明文解密器：返回值含 C1 控制符 0x7F（plainUtf16Ok 拒收）。
Bytes buildBadPlainDecryptor()
{
    FixtureBuilder builder("pkg/Bad");
    // U+007F DEL 在 MUTF-8 中为单字节 0x7F。
    FixtureMethod m;
    m.name      = "a";
    m.desc      = "(Ljava/lang/String;)Ljava/lang/String;";
    m.access    = kDecryptorAccess;
    m.maxStack  = 2;
    m.maxLocals = 1;
    m.code      = buildIdentityDecryptorBody(builder, "\x7F");
    builder.addMethod(m);
    return builder.assemble();
}

/// 重读容器内 class 资源（不可解析即断言失败）。
/// decodeCode 是非 const 突变缓存接口 → 返回非 const 引用。
jbc::core::ClassFile& readClassResource(mjbase::model::ResourceContainer& container,
                                        const char* uri)
{
    static std::unique_ptr<jbc::core::ClassFile> keeper;
    auto* resource = container.getResource(uri);
    EXPECT_NE(resource, nullptr);
    auto* cls = ca::core::tag_cast::cast<mjbase::model::ClassResource>(resource);
    EXPECT_NE(cls, nullptr);
    keeper = nullptr;
    if (cls != nullptr) {
        auto read = jbc::core::readClass(jbc::core::ByteView(cls->get()));
        EXPECT_TRUE(read.is_ok());
        if (read.is_ok()) keeper = std::move(read).unwrap().file;
    }
    // 无法解析时返回一个静态空对象，避免解引用 nullptr。
    static jbc::core::ClassFile fallback;
    return keeper ? *keeper : fallback;
}

const jbc::core::MemberInfo* findMethod(const jbc::core::ClassFile& cf, const char* name)
{
    for (const jbc::core::MemberInfo& m : cf.methods) {
        if (cf.nameOf(m) == name) return &m;
    }
    return nullptr;
}

/// 提取方法 Code 属性首条指令的 ldc 常量字符串（改写断言用）。
/// 返回空串表示未找到 ldc 或 CP 条目非 String。
/// decodeCode 是非 const 突变缓存接口：const ClassFile/MemberInfo → 非 const 引用。
std::string firstLdcString(const jbc::core::ClassFile& cfRaw, const jbc::core::MemberInfo& mRaw)
{
    auto& cf = const_cast<jbc::core::ClassFile&>(cfRaw);
    auto& m = const_cast<jbc::core::MemberInfo&>(mRaw);
    auto  d = cf.decodeCode(m);
    if (d.is_err()) return {};
    const jbc::core::CodeAttr* code = std::move(d).unwrap();
    if (code == nullptr || code->code.size() < 2) return {};
    // 首条指令 ldc (0x12) 或 ldc_w (0x13)。
    if (code->code[0] != 0x12 && code->code[0] != 0x13) return {};
    const ca::u16 idx = (code->code[0] == 0x13)
        ? static_cast<ca::u16>((code->code[1] << 8) | code->code[2])
        : code->code[1];
    if (!cf.cp.valid(idx)) return {};
    const auto& entry = cf.cp.at(idx);
    if (entry.tag != jbc::core::CpTag::String) return {};
    return std::string(cf.utf8(entry.a));
}

/// 运行 pass 并返回 PreservedAnalyses。
mjbase::spi::PreservedAnalyses runPass(mjbase::model::ResourceContainer& container)
{
    allatori::AllatoriStringDecryptPass   pass;
    ca::str::Utf8StringArena                 arena;
    mjbase::spi::GlobalAnalysisManager       gam(arena);
    return pass.run(container, gam);
}

}   // namespace

// ── 用例一：正常改写 ──
// 解密器返回 "Hello"；调用方 ldc "X" + invokestatic → ldc "Hello"，invokestatic 被擦除。
TEST(MjPassAllatoriStringDecryptTest, RewritesCallSiteToPlaintext)
{
    mjbase::model::ResourceContainer container;
    addClassResource(container, "pkg/Dec.class",
                     buildDecryptorClass("pkg/Dec", "Hello"));
    addClassResource(container, "pkg/Caller.class",
                     buildCallerClass("pkg/Caller", "pkg/Dec", "X"));

    const auto pa = runPass(container);
    EXPECT_TRUE(pa.changed());

    const jbc::core::ClassFile& caller = readClassResource(container, "pkg/Caller.class");
    const auto* call = findMethod(caller, "call");
    ASSERT_NE(call, nullptr);
    // 首条指令 ldc 应为 "Hello"；invokestatic 已擦除 → 方法码更短。
    EXPECT_EQ(firstLdcString(caller, *call), "Hello");
}

// ── 用例二：native 解密器跳过 ──
// ACC_NATIVE 候选 → poisoned，调用方保持原样。
TEST(MjPassAllatoriStringDecryptTest, SkipsNativeDecryptor)
{
    FixtureBuilder dec("pkg/NativeDec");
    FixtureMethod  m;
    m.name      = "a";
    m.desc      = "(Ljava/lang/String;)Ljava/lang/String;";
    m.access    = static_cast<ca::u16>(kDecryptorAccess | kAccNative);
    m.maxStack  = 2;
    m.maxLocals = 1;
    m.code      = buildIdentityDecryptorBody(dec, "Hello");
    dec.addMethod(m);

    mjbase::model::ResourceContainer container;
    addClassResource(container, "pkg/NativeDec.class", dec.assemble());
    addClassResource(container, "pkg/Caller.class",
                     buildCallerClass("pkg/Caller", "pkg/NativeDec", "X"));

    const auto pa = runPass(container);
    EXPECT_FALSE(pa.changed());   // 无改写

    const jbc::core::ClassFile& caller = readClassResource(container, "pkg/Caller.class");
    const auto* call = findMethod(caller, "call");
    ASSERT_NE(call, nullptr);
    // 首条 ldc 仍为 "X"（未改写）。
    EXPECT_EQ(firstLdcString(caller, *call), "X");
}

// ── 用例三：标签守卫跳过 ──
// invokestatic 前置边界有锚定标签（IFNE 分支目标）→ 跳过该点。
TEST(MjPassAllatoriStringDecryptTest, SkipsWhenLabelAnchorsCallSite)
{
    mjbase::model::ResourceContainer container;
    addClassResource(container, "pkg/Dec.class",
                     buildDecryptorClass("pkg/Dec", "Hello"));
    addClassResource(container, "pkg/Caller.class",
                     buildCallerClass("pkg/Caller", "pkg/Dec", "X", /*withLabelGuard=*/true));

    const auto pa = runPass(container);
    EXPECT_FALSE(pa.changed());   // 标签守卫命中 → 不改写

    const jbc::core::ClassFile& caller = readClassResource(container, "pkg/Caller.class");
    const auto* call = findMethod(caller, "call");
    ASSERT_NE(call, nullptr);
    // 首条 ldc 仍为 "X"（未改写；LDC 前还有 ICONST_0，首条不是 ldc → 空）。
    EXPECT_EQ(firstLdcString(caller, *call), "");
}

// ── 用例四：链式连调 fixpoint ──
// Strong 返回 "Hello"，Weak 返回 "World"；调用方 seed → Strong → Weak。
// 第一轮：Strong 改写为 ldc "Hello"；第二轮：Weak 改写为 ldc "World"。
TEST(MjPassAllatoriStringDecryptTest, ResolvesChainedDecryptorsViaFixpoint)
{
    mjbase::model::ResourceContainer container;
    addClassResource(container, "pkg/Strong.class", buildStrongDecryptor());
    addClassResource(container, "pkg/Weak.class", buildWeakDecryptor());
    addClassResource(container, "pkg/Caller.class", buildChainCaller());

    const auto pa = runPass(container);
    EXPECT_TRUE(pa.changed());

    const jbc::core::ClassFile& caller = readClassResource(container, "pkg/Caller.class");
    const auto* call = findMethod(caller, "call");
    ASSERT_NE(call, nullptr);
    // 首条 ldc 为 "World"（链末端明文）。
    EXPECT_EQ(firstLdcString(caller, *call), "World");
}

// ── 用例四B：双层链中间态含控制符仍可折叠 ──
// 双层加密链 ldc;Strong;Weak：Strong 返回中间态含 U+0006（C0 控制符，若按
// 单层明文兜底会被 plainUtf16Ok 拒收 → 链首层静默失败，整链丢弃）。
// 链首结果是密文而非明文 → 免兜底；Weak 末端照常全量校验，两层均折叠。
TEST(MjPassAllatoriStringDecryptTest, RewritesChainWithControlCharIntermediate)
{
    mjbase::model::ResourceContainer container;
    addClassResource(container, "pkg/Strong.class",
                     buildDecryptorClass("pkg/Strong", "\x06"));
    addClassResource(container, "pkg/Weak.class",
                     buildDecryptorClass("pkg/Weak", "Final"));
    addClassResource(container, "pkg/Caller.class", buildChainCaller());

    const auto pa = runPass(container);
    EXPECT_TRUE(pa.changed());

    const jbc::core::ClassFile& caller = readClassResource(container, "pkg/Caller.class");
    const auto* call = findMethod(caller, "call");
    ASSERT_NE(call, nullptr);
    // 两层全部折叠：首条 ldc 为末端明文 "Final"（非 "seed" 也非中间态 "\x06"）。
    EXPECT_EQ(firstLdcString(caller, *call), "Final");

    // invokestatic 全部擦除（两层都被改写）。
    auto& cf = const_cast<jbc::core::ClassFile&>(caller);
    auto& m = const_cast<jbc::core::MemberInfo&>(*call);
    auto  d = cf.decodeCode(m);
    ASSERT_TRUE(d.is_ok());
    const jbc::core::CodeAttr* codeAttr = std::move(d).unwrap();
    ASSERT_NE(codeAttr, nullptr);
    auto insns = jbc::core::decodeInsns(jbc::core::ByteView(codeAttr->code));
    ASSERT_TRUE(insns.is_ok());
    int invokeStatics = 0;
    for (const auto& in : std::move(insns).unwrap()) {
        if (in.op == jbc::core::Op::INVOKESTATIC) ++invokeStatics;
    }
    EXPECT_EQ(invokeStatics, 0);
}

// ── 用例五：非法明文拒写 ──
// 解密器返回含 C1 控制符 U+007F 的字符串 → 解释成功但 plainUtf16Ok 拒收 → 不改写。
TEST(MjPassAllatoriStringDecryptTest, RejectsInvalidPlaintext)
{
    mjbase::model::ResourceContainer container;
    addClassResource(container, "pkg/Bad.class", buildBadPlainDecryptor());
    addClassResource(container, "pkg/Caller.class",
                     buildCallerClass("pkg/Caller", "pkg/Bad", "X"));

    const auto pa = runPass(container);
    EXPECT_FALSE(pa.changed());

    const jbc::core::ClassFile& caller = readClassResource(container, "pkg/Caller.class");
    const auto* call = findMethod(caller, "call");
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(firstLdcString(caller, *call), "X");
}

// ── 用例六：非解密器签名不误伤 ──
// 同签名但缺 static/synthetic 位 → 非解密器，调用方不改写。
TEST(MjPassAllatoriStringDecryptTest, IgnoresNonDecryptorAccess)
{
    FixtureBuilder dec("pkg/NotDec");
    FixtureMethod  m;
    m.name      = "a";
    m.desc      = "(Ljava/lang/String;)Ljava/lang/String;";
    m.access    = kAccPublic;   // 缺 static+synthetic
    m.maxStack  = 2;
    m.maxLocals = 1;
    m.code      = buildIdentityDecryptorBody(dec, "Hello");
    dec.addMethod(m);

    mjbase::model::ResourceContainer container;
    addClassResource(container, "pkg/NotDec.class", dec.assemble());
    addClassResource(container, "pkg/Caller.class",
                     buildCallerClass("pkg/Caller", "pkg/NotDec", "X"));

    const auto pa = runPass(container);
    EXPECT_FALSE(pa.changed());

    const jbc::core::ClassFile& caller = readClassResource(container, "pkg/Caller.class");
    const auto* call = findMethod(caller, "call");
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(firstLdcString(caller, *call), "X");
}

// ── 用例七：单方法 >8 处调用点全量改写 ──
// fixpoint 每轮至多重写一处（erase 后 ids 快照失效须重扫），轮数上界须随
// 方法规模增长；旧实现固定轮上限 8 导致单方法第 9 处起静默丢弃。
TEST(MjPassAllatoriStringDecryptTest, RewritesMoreThanEightSitesInOneMethod)
{
    constexpr int kSites = 12;

    FixtureBuilder builder("pkg/ManyCaller");
    const ca::u16  dref =
        builder.methodRef("pkg/Dec", "a", "(Ljava/lang/String;)Ljava/lang/String;");
    Bytes code;
    for (int i = 0; i < kSites; ++i) {
        const ca::u16 cconst = builder.strConst("c" + std::to_string(i));
        code.push_back(0x12);
        code.push_back(static_cast<ca::u8>(cconst));
        code.push_back(0xB8);
        code.push_back(static_cast<ca::u8>(dref >> 8));
        code.push_back(static_cast<ca::u8>(dref));
    }
    code.push_back(0xB0);   // ARETURN

    FixtureMethod fm;
    fm.name      = "call";
    fm.desc      = "()Ljava/lang/String;";
    fm.access    = static_cast<ca::u16>(kAccPublic | kAccStatic);
    fm.maxStack  = 1;
    fm.maxLocals = 0;
    fm.code      = std::move(code);
    builder.addMethod(fm);

    mjbase::model::ResourceContainer container;
    addClassResource(container, "pkg/Dec.class",
                     buildDecryptorClass("pkg/Dec", "Hello"));
    addClassResource(container, "pkg/ManyCaller.class", builder.assemble());

    const auto pa = runPass(container);
    EXPECT_TRUE(pa.changed());

    const jbc::core::ClassFile& caller = readClassResource(container, "pkg/ManyCaller.class");
    const auto* call = findMethod(caller, "call");
    ASSERT_NE(call, nullptr);

    // 全部 invokestatic 已擦除，且全部 ldc 已折叠为同一明文。
    auto& cf = const_cast<jbc::core::ClassFile&>(caller);
    auto& m = const_cast<jbc::core::MemberInfo&>(*call);
    auto  d = cf.decodeCode(m);
    ASSERT_TRUE(d.is_ok());
    const jbc::core::CodeAttr* codeAttr = std::move(d).unwrap();
    ASSERT_NE(codeAttr, nullptr);
    auto insns = jbc::core::decodeInsns(jbc::core::ByteView(codeAttr->code));
    ASSERT_TRUE(insns.is_ok());
    int plainLdcs = 0;
    int invokeStatics = 0;
    for (const auto& in : std::move(insns).unwrap()) {
        if (in.op == jbc::core::Op::INVOKESTATIC) ++invokeStatics;
        if (in.op == jbc::core::Op::LDC || in.op == jbc::core::Op::LDC_W) {
            const ca::u16 idx = static_cast<ca::u16>(in.cp);
            if (cf.cp.valid(idx) && cf.cp.at(idx).tag == jbc::core::CpTag::String &&
                cf.utf8(cf.cp.at(idx).a) == "Hello")
            {
                ++plainLdcs;
            }
        }
    }
    EXPECT_EQ(invokeStatics, 0);
    EXPECT_EQ(plainLdcs, kSites);
}

// ── 集成测试：真实 Allatori 9.9 混淆 jar ──
// 从 lab-9.9 目录加载 Allatori 混淆产物，运行 pass，验证已知明文出现在输出中。
// lab 目录不存在时跳过（GTEST_SKIP）。

namespace {

/// lab 语料目录：环境变量 ALLATORI_LAB_DIR（含 obf-fast.jar 等语料）；
/// 未设置时集成用例 skip。
const char* labDir()
{
    return std::getenv("ALLATORI_LAB_DIR");
}

/// 收集容器中所有 class 资源里所有 ldc 常量字符串（改写断言用）。
std::vector<std::string> collectAllLdcStrings(mjbase::model::ResourceContainer& container)
{
    std::vector<std::string> result;
    for (const auto& [uri, resource] : container.getResources()) {
        if (!resource) continue;
        if (!ca::core::tag_cast::isa<mjbase::model::ClassResource>(resource.get())) continue;
        auto* cls = ca::core::tag_cast::cast<mjbase::model::ClassResource>(resource.get());
        if (cls == nullptr) continue;
        const auto& bytes = cls->get();
        if (bytes.size() < 4) continue;
        // Check magic number (0xCAFEBABE)
        if (bytes[0] != 0xCA || bytes[1] != 0xFE || bytes[2] != 0xBA || bytes[3] != 0xBE) continue;
        auto read = jbc::core::readClass(jbc::core::ByteView(bytes));
        if (read.is_err()) continue;
        // ReadResult 必须存活到 cf 使用结束（.file 的 unique_ptr 持有 ClassFile）。
        jbc::core::ReadResult rr = std::move(read).unwrap();
        if (!rr.file) continue;
        auto& cf = *rr.file;
        for (jbc::core::MemberInfo& m : cf.methods) {
            auto d = cf.decodeCode(m);
            if (d.is_err()) continue;
            const jbc::core::CodeAttr* code = std::move(d).unwrap();
            if (code == nullptr || code->code.empty()) continue;
            auto insns = jbc::core::decodeInsns(jbc::core::ByteView(code->code));
            if (insns.is_err()) continue;
            for (const auto& in : std::move(insns).unwrap()) {
                if (in.op == jbc::core::Op::LDC || in.op == jbc::core::Op::LDC_W) {
                    const ca::u16 idx = static_cast<ca::u16>(in.cp);
                    if (cf.cp.valid(idx) && cf.cp.at(idx).tag == jbc::core::CpTag::String)
                        result.emplace_back(cf.utf8(cf.cp.at(idx).a));
                }
            }
        }
    }
    return result;
}

/// 检查字符串列表中是否包含目标串。
bool contains(const std::vector<std::string>& v, const std::string& target)
{
    for (const auto& s : v) {
        if (s == target) return true;
    }
    return false;
}

}   // namespace

// ── 集成用例：Allatori 9.9 fast 档 ──
// 已知明文："Snake"、"Yummy!"、"COLISION! \n"
// 混淆后密文："o\u000e]\u000bY"、"U\u001ca\u0004uH"、"*C%E:E&BH,c"
TEST(MjPassAllatoriStringDecryptTest, DecryptsRealAllatoriFastJar)
{
    const char* lab = labDir();
    if (lab == nullptr) {
        GTEST_SKIP() << "ALLATORI_LAB_DIR not set";
    }
    const std::string jarPath = std::string(lab) + "\\obf-fast.jar";
    if (!std::filesystem::exists(jarPath)) {
        GTEST_SKIP() << "lab jar not found: " << jarPath;
    }

    mjbase::model::ResourceContainer container;
    auto importResult = mjbase::model::ResourceHelper::importFromJar(container, jarPath);
    ASSERT_TRUE(importResult.is_ok()) << "failed to import jar: " << jarPath;

    const auto pa = runPass(container);
    EXPECT_TRUE(pa.changed());   // fast 档 3 个调用点应全部改写

    const auto strings = collectAllLdcStrings(container);
    // 已知明文应出现
    EXPECT_TRUE(contains(strings, "Snake")) << "plaintext 'Snake' not found";
    EXPECT_TRUE(contains(strings, "Yummy!")) << "plaintext 'Yummy!' not found";
    EXPECT_TRUE(contains(strings, "COLISION! \n")) << "plaintext 'COLISION! \\n' not found";
    // 密文应消失
    EXPECT_FALSE(contains(strings, "o\u000e]\u000bY")) << "ciphertext still present";
    EXPECT_FALSE(contains(strings, "U\u001ca\u0004uH")) << "ciphertext still present";
    EXPECT_FALSE(contains(strings, "*C%E:E&BH,c")) << "ciphertext still present";
}

// ── 集成用例：Allatori 9.9 strong 档 ──
// 已知明文："Snake"、"Yummy!"、"COLISION! \n"
// 混淆后密文："\u000eg4e7"、"\u0017A*P)\u000b"、"i\u0002{...\u001cp"
TEST(MjPassAllatoriStringDecryptTest, DecryptsRealAllatoriStrongJar)
{
    const char* lab = labDir();
    if (lab == nullptr) {
        GTEST_SKIP() << "ALLATORI_LAB_DIR not set";
    }
    const std::string jarPath = std::string(lab) + "\\obf-strong.jar";
    if (!std::filesystem::exists(jarPath)) {
        GTEST_SKIP() << "lab jar not found: " << jarPath;
    }

    mjbase::model::ResourceContainer container;
    auto importResult = mjbase::model::ResourceHelper::importFromJar(container, jarPath);
    ASSERT_TRUE(importResult.is_ok()) << "failed to import jar: " << jarPath;

    const auto pa = runPass(container);
    EXPECT_TRUE(pa.changed());   // strong 档 3 个调用点应全部改写

    const auto strings = collectAllLdcStrings(container);
    EXPECT_TRUE(contains(strings, "Snake")) << "plaintext 'Snake' not found";
    EXPECT_TRUE(contains(strings, "Yummy!")) << "plaintext 'Yummy!' not found";
    EXPECT_TRUE(contains(strings, "COLISION! \n")) << "plaintext 'COLISION! \\n' not found";
    // 密文应消失（strong 档密文含不可打印字符，用精确匹配）
    EXPECT_FALSE(contains(strings, "\u000eg4e7")) << "ciphertext still present";
    EXPECT_FALSE(contains(strings, "\u0017A*P)\u000b")) << "ciphertext still present";
}

// ── 集成用例：Allatori 9.9 off 档（无加密，pass 应无改动）──
TEST(MjPassAllatoriStringDecryptTest, NoOpOnUnencryptedJar)
{
    const char* lab = labDir();
    if (lab == nullptr) {
        GTEST_SKIP() << "ALLATORI_LAB_DIR not set";
    }
    const std::string jarPath = std::string(lab) + "\\SnakeGame.jar";
    if (!std::filesystem::exists(jarPath)) {
        GTEST_SKIP() << "lab jar not found: " << jarPath;
    }

    mjbase::model::ResourceContainer container;
    auto importResult = mjbase::model::ResourceHelper::importFromJar(container, jarPath);
    ASSERT_TRUE(importResult.is_ok()) << "failed to import jar: " << jarPath;

    const auto pa = runPass(container);
    EXPECT_FALSE(pa.changed());   // 无加密 → 无改写

    const auto strings = collectAllLdcStrings(container);
    EXPECT_TRUE(contains(strings, "Snake")) << "plaintext 'Snake' not found";
}

// ── pack 缝合：同源门 + 插件注册贯通 ──

TEST(AllatoriPack, installRegistersNamespacedPasses)
{
    mjbase::spi::PassNameRegistry registry;
    ca::core::Result<void, mjbase::plugin::PackError> r =
        mjbase::plugin::installPack(allatori::allatori_pack(), registry, "");
    ASSERT_TRUE(r.is_ok()) << mjbase::plugin::to_string(r.unwrap_err().kind) << ": "
                           << r.unwrap_err().detail;

    EXPECT_TRUE(registry.has("allatori.StringDecrypt"));
    auto created = registry.createGlobalPass("allatori.StringDecrypt");
    ASSERT_TRUE(created.is_ok());
    EXPECT_NE(std::move(created).unwrap(), nullptr);
}
