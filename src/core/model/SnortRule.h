#pragma once

/// SnortRule — parsed representation of a Snort 3.x rule.
///
/// The AST produced by SnortRuleParser. Contains the rule header
/// (action, protocol, IPs, ports, direction) and all parsed options
/// (content, PCRE, flow, flowbits, threshold, metadata).

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace nids::core {

struct SnortRule {
    // ── Header ──────────────────────────────────────────────────────

    enum class Action : std::uint8_t {
        Alert, Log, Pass, Drop, Reject, SDrop
    };
    Action action = Action::Alert;

    std::uint8_t protocol = 0; ///< IPPROTO_TCP (6), IPPROTO_UDP (17), etc.
    std::string srcIp;         ///< May be variable ($HOME_NET)
    std::string srcPort;       ///< "any", "80", "[80,443]", "1024:"
    std::string dstIp;
    std::string dstPort;
    bool bidirectional = false; ///< <> vs ->

    // ── Content match option ────────────────────────────────────────

    struct ContentOption {
        std::vector<std::uint8_t> pattern; ///< Byte pattern (text or hex)
        bool nocase = false;
        bool negated = false;              ///< ! prefix
        std::optional<int> offset;
        std::optional<int> depth;
        std::optional<int> distance;
        std::optional<int> within;
    };

    // ── PCRE match option ───────────────────────────────────────────

    struct PcreOption {
        std::string pattern;      ///< Regex pattern
        std::string modifiers;    ///< "i", "s", "m", etc.
        bool negated = false;
        bool relative = false;    ///< "R" modifier
    };

    // ── Flow option ─────────────────────────────────────────────────

    struct FlowOption {
        bool established = false;
        bool stateless = false;
        enum class Direction : std::uint8_t {
            Any, ToServer, ToClient, FromServer, FromClient
        } direction = Direction::Any;
    };

    // ── Flowbits option ─────────────────────────────────────────────

    struct FlowbitsOption {
        enum class Command : std::uint8_t {
            Set, Isset, Unset, Toggle, Noalert, IsnotSet
        } command = Command::Set;
        std::string name;
        std::optional<std::string> group;
    };

    // ── Threshold option ────────────────────────────────────────────

    struct ThresholdOption {
        enum class Type : std::uint8_t { Limit, Threshold, Both }
            type = Type::Limit;
        enum class Track : std::uint8_t { BySrc, ByDst }
            track = Track::BySrc;
        int count = 1;
        int seconds = 60;
    };

    // ── Collected options ───────────────────────────────────────────

    std::vector<ContentOption> contents;
    std::vector<PcreOption> pcres;
    std::optional<FlowOption> flow;
    std::vector<FlowbitsOption> flowbits;
    std::optional<ThresholdOption> threshold;

    // ── Metadata ────────────────────────────────────────────────────

    std::uint32_t sid = 0;
    std::uint32_t rev = 1;
    std::string msg;
    std::string classtype;
    int priority = 3;
    std::vector<std::pair<std::string, std::string>> references;
    std::vector<std::pair<std::string, std::string>> metadata;

    bool isEnabled = true;
};

} // namespace nids::core
