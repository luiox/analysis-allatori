#pragma once

#include "mjbase/plugin/pack.hpp"

namespace allatori {

/// 本仓唯一 pack 实例访问点（静态链接期入口；CLI 与测试共用）。
mjbase::plugin::IPassPack& allatori_pack();

}   // namespace allatori
