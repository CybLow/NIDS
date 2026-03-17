#pragma once

/// Abstract command interface for encapsulating capture operations.
///
/// Follows the Command pattern (AGENTS.md 5.7) to support undo, queuing,
/// and logging of capture lifecycle operations.

#include <string_view>

namespace nids::core {

class ICommand {
public:
    virtual ~ICommand() = default;

    /// Execute the command.
    virtual void execute() = 0;

    /// Undo the command (reverse the effect of execute).
    virtual void undo() = 0;

    /// Human-readable name for logging and auditing.
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
};

} // namespace nids::core
