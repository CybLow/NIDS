# ADR-003: Migrate from Qt5 to Qt6

## Status

Accepted (implemented in Phase 3)

## Context

The original NIDS used Qt5 for its GUI. Qt5 reached end-of-life for open-source users
and is no longer receiving feature updates. Qt6 is the current long-term supported
version with improved performance, better HiDPI support, and modernized APIs.

Issues with staying on Qt5:
- No new features or security patches after Qt 5.15 LTS
- Ubuntu 24.04 ships Qt6 as default; Qt5 packages becoming harder to find
- Cannot use Qt6-only features (e.g., improved property system, better CMake integration)
- vcpkg is transitioning to Qt6 as the primary Qt version

## Decision

Migrate from Qt5 to Qt6 with versionless CMake targets.

### CMake Changes
```cmake
# Before (Qt5)
find_package(Qt5 COMPONENTS Core Gui Widgets REQUIRED)
target_link_libraries(NIDS PRIVATE Qt5::Widgets Qt5::Core Qt5::Gui)

# After (Qt6, versionless targets)
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)
target_link_libraries(NIDS PRIVATE Qt::Widgets Qt::Core Qt::Gui)
```

### Source Changes
- Removed `QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling)` — this is
  the default behavior in Qt6.
- Verified all signal/slot connections use the new function pointer syntax (no
  string-based `SIGNAL()`/`SLOT()` macros).
- No API-breaking changes found in the widgets used by NIDS.

## Consequences

### Positive
- Long-term support: Qt6 LTS releases will continue to receive updates.
- Better HiDPI: Qt6 handles high-DPI displays natively without application-level opt-in.
- Improved CMake: Versionless targets (`Qt::Core`) make future major version transitions
  smoother.
- Consistent with CI and Docker environments (Ubuntu 24.04 ships `qt6-base-dev`).

### Negative
- Minimum system requirement now Ubuntu 22.04+ (Qt6 not available on older distros).
- Some third-party Qt5 widgets or plugins may not be compatible.
- Qt6 requires CMake 3.16+ (we already require 3.20).

### Simultaneously: C++20 Upgrade
The Qt6 migration was bundled with the C++17 -> C++20 upgrade:
- `CMAKE_CXX_STANDARD` set to `20`
- Enabled: `std::span`, `std::ranges`, `[[likely]]`/`[[unlikely]]`, concepts,
  `std::jthread`, `consteval`, designated initializers
- Updated `.clang-tidy` with C++20 modernize checks
