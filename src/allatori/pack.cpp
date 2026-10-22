#include "allatori/pack.hpp"

#include <string>

#include "allatori/string_decrypt_pass.hpp"

namespace allatori {

using ca::core::Err;
using ca::core::Ok;
using ca::core::Result;

namespace {

/// 家族 pack：manifest 声明构建戳与命名空间，注册委托各变换件的
/// registerAll。本 pack 暂无配置面，config 留空不解析。
class AllatoriPack final : public mjbase::plugin::IPassPack
{
public:
    const mjbase::plugin::PackManifest& manifest() const override { return manifest_; }

    Result<void, mjbase::plugin::PackError> registerPasses(mjbase::spi::PassNameRegistry& registry,
                                                           std::string_view config) override
    {
        static_cast<void>(config);
        if (Result<void, std::string> r = registerAll(registry); r.is_err()) {
            return Err(mjbase::plugin::makePackError(mjbase::plugin::PackErrorKind::RegistrationFailed,
                                                     r.unwrap_err()));
        }
        return Ok();
    }

private:
    mjbase::plugin::PackManifest manifest_{
        "allatori", mjbase::plugin::buildCommit(),
        "Allatori obfuscation family deobfuscation (string decryption; flow later)."};
};

AllatoriPack& packInstance()
{
    static AllatoriPack pack;
    return pack;
}

}   // namespace

mjbase::plugin::IPassPack& allatori_pack()
{
    return packInstance();
}

}   // namespace allatori
