#pragma once

/// Qt string conversion helpers for core domain types.
///
/// Eliminates repetitive `QString::fromUtf8(sv.data(),
/// static_cast<int>(sv.size()))` patterns scattered across UI code.  All
/// functions are inline / header-only.

#include "core/model/AttackType.h"
#include "core/model/DetectionSource.h"
#include "core/model/ProtocolConstants.h"

#include <QString>

#include <cstdint>
#include <string_view>

namespace nids::ui {

/// Convert a std::string_view to QString (UTF-8).
inline QString toQString(std::string_view sv) {
  return QString::fromUtf8(sv.data(), static_cast<int>(sv.size()));
}

/// Convert an AttackType enum to its display QString.
inline QString attackTypeQString(core::AttackType type) {
  return toQString(core::attackTypeToString(type));
}

/// Convert a DetectionSource enum to its display QString.
inline QString detectionSourceQString(core::DetectionSource src) {
  return toQString(core::detectionSourceToString(src));
}

/// Convert a protocol number to its display QString.
/// Returns "Other (N)" for unrecognized protocols.
inline QString protocolQString(std::uint8_t protocol) {
  if (auto name = core::protocolToName(protocol); name != "Other") {
    return toQString(name);
  }
  return QString("Other (%1)").arg(protocol);
}

} // namespace nids::ui
