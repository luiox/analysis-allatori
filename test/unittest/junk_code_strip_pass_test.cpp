// AllatoriJunkCodeStripPass 单测:死常量块 / 未折叠常量 / opaque 谓词(四形态)
// / while(false) / 字段毒化负例 / 注册面。
#include <gtest/gtest.h>

#include <functional>
#include <string>
#include <vector>

#include "jbc/core/opcode.hpp"

#include "allatori/junk_code_strip_pass.hpp"
#include "allatori/string_decrypt_pass.hpp"
#include "mjbase/spi/pass_name_registry.hpp"

#include "pass/method_pass_test_util.hpp"
#include "shared/structural_pass_util.hpp"

using namespace mjbase::test;
using allatori::AllatoriJunkCodeStripPass;
using jbc::core::Op;

namespace {

constexpr ca::u16 kAccPublicStatic = 0x0009;

/// 静态字段 j:I + <clinit> 单写 iconst_2 的宿主类外壳,追加 run 方法。
/// Fieldref 索引经 builder 现算,run 方法体由工厂按索引拼装。
Bytes buildFieldHost(std::string_view runName, std::string_view runDesc,
                     const std::function<Bytes(ca::u16)>& runCodeFn, ca::u16 runMaxStack,
                     bool extraStaticWrite = false)
{
    FixtureBuilder b("t/O");
    b.addField({"j", "I", kAccPublicStatic});
    const ca::u16 fref = b.fieldRef("t/O", "j", "I");

    FixtureMethod clinit;
    clinit.name     = "<clinit>";
    clinit.desc     = "()V";
    clinit.code     = {0x05, 0xb3, static_cast<ca::u8>(fref >> 8), static_cast<ca::u8>(fref),
                       0xb1};   // iconst_2; putstatic j; return
    b.addMethod(clinit);

    if (extraStaticWrite) {
        FixtureMethod setter;
        setter.name = "w";
        setter.desc = "()V";
        setter.code = {0x06, 0xb3, static_cast<ca::u8>(fref >> 8), static_cast<ca::u8>(fref),
                       0xb1};   // iconst_3; putstatic j; return
        b.addMethod(setter);
    }

    FixtureMethod run;
    run.name     = runName;
    run.desc     = runDesc;
    run.code     = runCodeFn(fref);
    run.maxStack = runMaxStack;
    b.addMethod(run);
    return b.assemble();
}

/// getstatic j 的三字节序列。
Bytes getJ(ca::u16 fref)
{
    return {0xb2, static_cast<ca::u8>(fref >> 8), static_cast<ca::u8>(fref)};
}

}   // namespace

// 死常量块:sipush×4 + pop2×2 → 全清,只剩 return。
TEST(JunkCodeStripTest, removesDeadConstantBlock)
{
    FixtureBuilder b("t/D");
    b.addMethod({"m", "()V",
                 {0x11, 0xa6, 0x2f, 0x11, 0x94, 0xd3, 0x11, 0x7e, 0x34, 0x11, 0xee, 0x61,
                  0x58, 0x58, 0xb1}});
    const MethodPassRun r = runMethodPass(b.assemble(), AllatoriJunkCodeStripPass{});

    EXPECT_TRUE(r.pa.changed());
    const Inspection      ins = inspect(r.out);
    const std::vector<Op> ops  = opsOf(ins);
    ASSERT_EQ(ops.size(), 1u);
    EXPECT_EQ(ops[0], Op::RETURN);
}

// 未折叠常量表达式:sipush 4369; sipush 8738; iand → 单常量 + ireturn。
TEST(JunkCodeStripTest, foldsUnfoldedConstantExpression)
{
    FixtureBuilder b("t/C");
    b.addMethod({"m", "()I", {0x11, 0x0f, 0xbc, 0x11, 0x71, 0x6f, 0x7e, 0xac}});
    const MethodPassRun r = runMethodPass(b.assemble(), AllatoriJunkCodeStripPass{});

    EXPECT_TRUE(r.pa.changed());
    const Inspection      ins = inspect(r.out);
    const std::vector<Op> ops  = opsOf(ins);
    ASSERT_EQ(ops.size(), 2u);
    EXPECT_EQ(ops[0], Op::SIPUSH);
    EXPECT_EQ(ops[1], Op::IRETURN);
}

// opaque 谓词恒假:getstatic j(=2); iconst_2; if_icmpNE → 三分支指令全删,
// 恒定 fallthrough 路径保留,另一路径成死段被 DCE。
TEST(JunkCodeStripTest, opaquePredicateFalseErase)
{
    // run()I: getstatic; iconst_2; if_icmpNE L(+3); iconst_3; ireturn; L: iconst_4; ireturn
    const Bytes in = buildFieldHost(
        "run", "()I",
        [](ca::u16 f) {
            Bytes code = getJ(f);
            const Bytes tail = {0x05, 0xa0, 0x00, 0x05, 0x06, 0xac, 0x07, 0xac};
            code.insert(code.end(), tail.begin(), tail.end());
            return code;
        },
        2);
    const MethodPassRun r = runMethodPass(in, AllatoriJunkCodeStripPass{});

    EXPECT_TRUE(r.pa.changed());
    const Inspection      ins = inspect(r.out, 1);
    const std::vector<Op> ops  = opsOf(ins);
    ASSERT_EQ(ops.size(), 2u);
    EXPECT_EQ(ops[0], Op::ICONST_3);
    EXPECT_EQ(ops[1], Op::IRETURN);
}

// opaque 谓词恒真(逆序操作数):iconst_2; getstatic j; if_icmpEQ → if 原地变
// GOTO,前缀删除,fallthrough 路径死段被 DCE。
TEST(JunkCodeStripTest, opaquePredicateTrueGotoReversedOperands)
{
    // run()I: iconst_2; getstatic; if_icmpEQ L(+3); iconst_4; ireturn; L: iconst_3; ireturn
    const Bytes in = buildFieldHost(
        "run", "()I",
        [](ca::u16 f) {
            Bytes code = {0x05};
            const Bytes g = getJ(f);
            code.insert(code.end(), g.begin(), g.end());
            const Bytes tail = {0x9f, 0x00, 0x05, 0x07, 0xac, 0x06, 0xac};
            code.insert(code.end(), tail.begin(), tail.end());
            return code;
        },
        2);
    const MethodPassRun r = runMethodPass(in, AllatoriJunkCodeStripPass{});

    EXPECT_TRUE(r.pa.changed());
    const Inspection      ins = inspect(r.out, 1);
    const std::vector<Op> ops  = opsOf(ins);
    ASSERT_EQ(ops.size(), 3u);
    EXPECT_EQ(ops[0], Op::GOTO);
    EXPECT_EQ(ops[1], Op::ICONST_3);
    EXPECT_EQ(ops[2], Op::IRETURN);
}

// opaque 谓词单操作数:getstatic j(≠0); ifne → GOTO,另一路径删除。
TEST(JunkCodeStripTest, opaquePredicateTrueGotoUnop)
{
    // run()I: getstatic; ifne L(+2); iconst_4; ireturn; L: iconst_3; ireturn
    const Bytes in = buildFieldHost(
        "run", "()I",
        [](ca::u16 f) {
            Bytes code = getJ(f);
            const Bytes tail = {0x9a, 0x00, 0x05, 0x07, 0xac, 0x06, 0xac};
            code.insert(code.end(), tail.begin(), tail.end());
            return code;
        },
        1);
    const MethodPassRun r = runMethodPass(in, AllatoriJunkCodeStripPass{});

    EXPECT_TRUE(r.pa.changed());
    const Inspection      ins = inspect(r.out, 1);
    const std::vector<Op> ops  = opsOf(ins);
    ASSERT_EQ(ops.size(), 3u);
    EXPECT_EQ(ops[0], Op::GOTO);
    EXPECT_EQ(ops[1], Op::ICONST_3);
    EXPECT_EQ(ops[2], Op::IRETURN);
}

// while(false):iconst_0; ifne L → 无字段也命中(常量单操作数形态),死体清除。
TEST(JunkCodeStripTest, whileFalseRemovedWithoutField)
{
    // run()V: iconst_0; ifne L(+2); iconst_1; pop; L: return
    FixtureBuilder b("t/W");
    b.addMethod({"m", "()V", {0x03, 0x9a, 0x00, 0x05, 0x04, 0x57, 0xb1}});
    const MethodPassRun r = runMethodPass(b.assemble(), AllatoriJunkCodeStripPass{});

    EXPECT_TRUE(r.pa.changed());
    const Inspection      ins = inspect(r.out);
    const std::vector<Op> ops  = opsOf(ins);
    ASSERT_EQ(ops.size(), 1u);
    EXPECT_EQ(ops[0], Op::RETURN);
}

// 字段毒化负例:<clinit> 外还有 putstatic → 终值不采信,谓词原样保留(字节等变)。
TEST(JunkCodeStripTest, poisonedFieldLeavesPredicateIntact)
{
    // run()I: getstatic; iconst_2; if_icmpNE L(+3); iconst_3; ireturn; L: iconst_4; ireturn
    const Bytes in = buildFieldHost(
        "run", "()I",
        [](ca::u16 f) {
            Bytes code = getJ(f);
            const Bytes tail = {0x05, 0xa0, 0x00, 0x05, 0x06, 0xac, 0x07, 0xac};
            code.insert(code.end(), tail.begin(), tail.end());
            return code;
        },
        2,
        /*extraStaticWrite=*/true);
    const MethodPassRun r = runMethodPass(in, AllatoriJunkCodeStripPass{});

    EXPECT_TRUE(r.pa.areAllPreserved());
    EXPECT_FALSE(r.pa.changed());
    EXPECT_EQ(r.out, in);
}

// 注册面:registerAll 装入两个 allatori pass。
TEST(JunkCodeStripTest, registersInPackRegistry)
{
    mjbase::spi::PassNameRegistry reg;
    const auto                    r = allatori::registerAll(reg);
    ASSERT_TRUE(r.is_ok());
    EXPECT_TRUE(reg.has("allatori.StringDecrypt"));
    EXPECT_TRUE(reg.has("allatori.JunkCodeStrip"));
    const auto entry = reg.find("allatori.JunkCodeStrip");
    ASSERT_TRUE(entry.is_ok());
    EXPECT_EQ(entry.unwrap().scope, mjbase::spi::PassScope::Method);
}
