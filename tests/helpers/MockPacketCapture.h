#pragma once

/// Shared mock for IPacketCapture.
///
/// Consolidates MockPacketCapture, MockCapture, and MockCaptureCmds
/// into a single reusable header.

#include <gmock/gmock.h>

#include "core/services/IPacketCapture.h"

#include <expected>
#include <string>
#include <vector>

namespace nids::testing {

class MockPacketCapture : public core::IPacketCapture {
public:
    MOCK_METHOD((std::expected<void, std::string>), initialize,
                (const std::string&, const std::string&), (override));
    MOCK_METHOD(void, startCapture, (const std::string&), (override));
    MOCK_METHOD(void, stopCapture, (), (override));
    MOCK_METHOD(bool, isCapturing, (), (const, override));
    MOCK_METHOD(void, setPacketCallback, (PacketCallback), (override));
    MOCK_METHOD(void, setErrorCallback, (ErrorCallback), (override));
    MOCK_METHOD(void, setRawPacketCallback, (RawPacketCallback), (override));
    MOCK_METHOD(std::vector<std::string>, listInterfaces, (), (const, override));
};

} // namespace nids::testing
