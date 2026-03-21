#pragma once

// FlowKey has moved to core/model/FlowKey.h.
// This header provides a namespace alias for infra code that still
// references nids::infra::FlowKey.

#include "core/model/FlowKey.h"

namespace nids::infra {
using FlowKey = core::FlowKey;
using FlowKeyHash = core::FlowKeyHash;
} // namespace nids::infra
