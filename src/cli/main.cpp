/// @file        main.cpp
/// @brief       allatori CLI：装 pack → 导 jar → 管线 → 导 jar。
///
/// 各插件仓自组 CLI：mjbase 出框架（注册表/管线/容器 IO/workspace 装配），
/// 本仓只出 pack 与 pass。装配走 plugin-api.md 宿主配方的静态链接形态。
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "allatori/pack.hpp"
#include "mjbase/log/log_init.hpp"
#include "mjbase/model/resource_container.hpp"
#include "mjbase/model/resource_helper.hpp"
#include "mjbase/plugin/pack.hpp"
#include "mjbase/spi/job_context.hpp"
#include "mjbase/spi/pass_manager.hpp"
#include "mjbase/spi/pass_name_registry.hpp"
#include "mjbase/spi/pipeline_builder.hpp"

namespace {

constexpr const char* kUsage =
    "allatori_cli -i in.jar -o out.jar -p allatori.X[,allatori.Y...] [-c pack.json]\n"
    "  -i  输入 jar\n"
    "  -o  输出 jar\n"
    "  -p  逗号分隔 pass 名（allatori. 前缀）\n"
    "  -c  pack 配置 JSON 文件（可选，文本整体交给 pack 解析）\n"
    "  --list  列出本 pack 注册的全部 pass 后退出\n";

std::string readFileText(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::vector<std::string> splitNames(const std::string& list)
{
    std::vector<std::string> out;
    std::string item;
    std::istringstream ss(list);
    while (std::getline(ss, item, ',')) {
        if (!item.empty()) out.push_back(item);
    }
    return out;
}

}   // namespace

int main(int argc, char** argv)
{
    mjbase::log::initDefaultLogger();

    std::string input;
    std::string output;
    std::string passList;
    std::string configPath;
    bool        list = false;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--list") {
            list = true;
        } else if (arg == "-i" && i + 1 < argc) {
            input = argv[++i];
        } else if (arg == "-o" && i + 1 < argc) {
            output = argv[++i];
        } else if (arg == "-p" && i + 1 < argc) {
            passList = argv[++i];
        } else if (arg == "-c" && i + 1 < argc) {
            configPath = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            std::fputs(kUsage, stdout);
            return 0;
        } else {
            std::fprintf(stderr, "未知参数：%s\n%s", arg.c_str(), kUsage);
            return 2;
        }
    }

    std::string configText;
    if (!configPath.empty()) {
        configText = readFileText(configPath);
        if (configText.empty()) {
            std::fprintf(stderr, "配置文件为空或不可读：%s\n", configPath.c_str());
            return 2;
        }
    }

    // 装配（plugin-api.md 宿主配方）：宿主自持注册表，逐 pack 装入，
    // allatori. 前缀与同源门由 installPack 机械验收。
    mjbase::spi::PassNameRegistry registry;
    if (ca::core::Result<void, mjbase::plugin::PackError> r =
            mjbase::plugin::installPack(allatori::allatori_pack(), registry, configText);
        r.is_err()) {
        std::fprintf(stderr, "pack 装配失败：%s：%s\n", mjbase::plugin::to_string(r.unwrap_err().kind),
                     r.unwrap_err().detail.c_str());
        return 2;
    }

    if (list) {
        for (const auto& entry : registry.list()) {
            if (entry.name.substr(0, 9) == "allatori.") {
                std::printf("%.*s\t%.*s\n", static_cast<int>(entry.name.size()), entry.name.data(),
                            static_cast<int>(entry.description.size()), entry.description.data());
            }
        }
        return 0;
    }

    if (input.empty() || output.empty() || passList.empty()) {
        std::fputs(kUsage, stderr);
        return 2;
    }

    mjbase::spi::PipelineBuilder builder;
    for (const std::string& name : splitNames(passList)) {
        if (auto r = mjbase::spi::applyTo(registry, name, builder); r.is_err()) {
            std::fprintf(stderr, "pass 装配失败：%s（%s）\n", name.c_str(),
                         mjbase::spi::to_string(r.unwrap_err()));
            return 2;
        }
    }

    mjbase::model::ResourceContainer container;
    if (auto m = mjbase::model::ResourceHelper::importFromJar(container, input); m.is_err()) {
        std::fprintf(stderr, "jar 导入失败（%s）：%s\n", mjbase::model::to_string(m.unwrap_err()),
                     input.c_str());
        return 2;
    }

    mjbase::spi::PassJobContext job;
    auto gpm = builder.buildNestedPipeline(job);
    if (auto r = mjbase::spi::runContainerPipeline(container, gpm, job); r.is_err()) {
        std::fprintf(stderr, "管线失败（%s@%s）：%s\n", mjbase::spi::to_string(r.unwrap_err().stage),
                     r.unwrap_err().target.c_str(), r.unwrap_err().detail.c_str());
        return 3;
    }

    if (auto m = mjbase::model::ResourceHelper::exportToJar(container, output); m.is_err()) {
        std::fprintf(stderr, "jar 导出失败（%s）：%s\n", mjbase::model::to_string(m.unwrap_err()),
                     output.c_str());
        return 2;
    }
    return 0;
}
