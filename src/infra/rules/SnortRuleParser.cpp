#include "infra/rules/SnortRuleParser.h"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <ranges>
#include <sstream>
#include <string>

namespace nids::infra {

namespace fs = std::filesystem;

namespace {

/// Trim whitespace from both ends.
[[nodiscard]] std::string_view trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front())))
        s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back())))
        s.remove_suffix(1);
    return s;
}

/// Split a string by delimiter, respecting quotes.
[[nodiscard]] std::vector<std::string_view> splitOptions(
    std::string_view opts) {
    std::vector<std::string_view> result;
    std::size_t start = 0;
    bool inQuote = false;
    int parenDepth = 0;

    for (std::size_t i = 0; i < opts.size(); ++i) {
        char c = opts[i];
        if (c == '"' && (i == 0 || opts[i - 1] != '\\')) {
            inQuote = !inQuote;
        } else if (c == '(' && !inQuote) {
            ++parenDepth;
        } else if (c == ')' && !inQuote) {
            --parenDepth;
        } else if (c == ';' && !inQuote && parenDepth == 0) {
            auto token = trim(opts.substr(start, i - start));
            if (!token.empty()) result.push_back(token);
            start = i + 1;
        }
    }
    // Last token
    auto token = trim(opts.substr(start));
    if (!token.empty()) result.push_back(token);
    return result;
}

/// Split key:value from an option token.
[[nodiscard]] std::pair<std::string_view, std::string_view> splitKeyValue(
    std::string_view opt) {
    auto colon = opt.find(':');
    if (colon == std::string_view::npos) {
        return {trim(opt), {}};
    }
    return {trim(opt.substr(0, colon)), trim(opt.substr(colon + 1))};
}

/// Remove surrounding quotes from a string.
[[nodiscard]] std::string_view unquote(std::string_view s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

/// Parse an integer from a string_view.
[[nodiscard]] int parseInt(std::string_view s, int defaultVal = 0) {
    s = trim(s);
    int val = defaultVal;
    std::from_chars(s.data(), s.data() + s.size(), val);
    return val;
}

/// Parse uint32 from a string_view.
[[nodiscard]] std::uint32_t parseUint32(std::string_view s) {
    s = trim(s);
    std::uint32_t val = 0;
    std::from_chars(s.data(), s.data() + s.size(), val);
    return val;
}

} // anonymous namespace

// ── Protocol mapping ────────────────────────────────────────────────

std::uint8_t SnortRuleParser::protocolFromString(
    std::string_view proto) noexcept {
    if (proto == "tcp") return 6;
    if (proto == "udp") return 17;
    if (proto == "icmp") return 1;
    // "ip" or unknown protocol → 0 (matches any IP protocol).
    return 0;
}

// ── Pattern decoding (text + |hex|) ─────────────────────────────────

std::vector<std::uint8_t> SnortRuleParser::decodePattern(
    std::string_view raw) {
    // Remove surrounding quotes if present.
    raw = unquote(raw);

    std::vector<std::uint8_t> result;
    bool inHex = false;

    for (std::size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] == '|') {
            inHex = !inHex;
            continue;
        }

        if (inHex) {
            // Skip spaces in hex mode.
            if (raw[i] == ' ') continue;
            // Parse hex byte.
            if (i + 1 < raw.size()) {
                char hi = raw[i];
                char lo = raw[i + 1];
                std::uint8_t byte = 0;
                std::from_chars(&hi, &hi + 1, byte, 16);
                byte <<= 4;
                std::uint8_t lo_val = 0;
                std::from_chars(&lo, &lo + 1, lo_val, 16);
                byte |= lo_val;
                result.push_back(byte);
                ++i; // Skip second hex char.
            }
        } else {
            // Handle escape sequences.
            if (raw[i] == '\\' && i + 1 < raw.size()) {
                ++i;
                switch (raw[i]) {
                    case '\\': result.push_back('\\'); break;
                    case '"':  result.push_back('"'); break;
                    case ';':  result.push_back(';'); break;
                    case ':':  result.push_back(':'); break;
                    default:   result.push_back(static_cast<std::uint8_t>(raw[i])); break;
                }
            } else {
                result.push_back(static_cast<std::uint8_t>(raw[i]));
            }
        }
    }
    return result;
}

// ── parse() ─────────────────────────────────────────────────────────

std::expected<core::SnortRule, std::string> SnortRuleParser::parse(
    std::string_view ruleText) const {

    ruleText = trim(ruleText);
    if (ruleText.empty() || ruleText[0] == '#') {
        return std::unexpected("Empty or comment line");
    }

    // Find the options block: everything inside (...)
    auto parenOpen = ruleText.find('(');
    if (parenOpen == std::string_view::npos) {
        return std::unexpected("No options block found (missing '(')");
    }

    auto parenClose = ruleText.rfind(')');
    if (parenClose == std::string_view::npos || parenClose <= parenOpen) {
        return std::unexpected("Malformed options block (missing ')')");
    }

    auto headerPart = trim(ruleText.substr(0, parenOpen));
    auto optionsPart = trim(ruleText.substr(parenOpen + 1,
                                             parenClose - parenOpen - 1));

    core::SnortRule rule;

    auto headerResult = parseHeader(headerPart, rule);
    if (!headerResult) {
        return std::unexpected(headerResult.error());
    }

    auto optionsResult = parseOptions(optionsPart, rule);
    if (!optionsResult) {
        return std::unexpected(optionsResult.error());
    }

    return rule;
}

// ── parseHeader() ───────────────────────────────────────────────────

std::expected<void, std::string> SnortRuleParser::parseHeader(
    std::string_view header, core::SnortRule& rule) const {

    // Split by whitespace: action protocol src_ip src_port dir dst_ip dst_port
    std::vector<std::string_view> tokens;
    std::size_t pos = 0;
    while (pos < header.size()) {
        // Skip whitespace.
        while (pos < header.size() && std::isspace(static_cast<unsigned char>(header[pos])))
            ++pos;
        if (pos >= header.size()) break;
        auto start = pos;
        while (pos < header.size() && !std::isspace(static_cast<unsigned char>(header[pos])))
            ++pos;
        tokens.push_back(header.substr(start, pos - start));
    }

    if (tokens.size() < 7) {
        return std::unexpected("Header requires 7 fields: "
                               "action protocol src_ip src_port dir dst_ip dst_port");
    }

    // Action
    auto actionStr = tokens[0];
    if (actionStr == "alert") rule.action = core::SnortRule::Action::Alert;
    else if (actionStr == "log") rule.action = core::SnortRule::Action::Log;
    else if (actionStr == "pass") rule.action = core::SnortRule::Action::Pass;
    else if (actionStr == "drop") rule.action = core::SnortRule::Action::Drop;
    else if (actionStr == "reject") rule.action = core::SnortRule::Action::Reject;
    else if (actionStr == "sdrop") rule.action = core::SnortRule::Action::SDrop;
    else return std::unexpected("Unknown action: " + std::string(actionStr));

    // Protocol
    rule.protocol = protocolFromString(tokens[1]);

    // Source
    rule.srcIp = std::string(tokens[2]);
    rule.srcPort = std::string(tokens[3]);

    // Direction
    auto dir = tokens[4];
    if (dir == "->") rule.bidirectional = false;
    else if (dir == "<>") rule.bidirectional = true;
    else return std::unexpected("Unknown direction: " + std::string(dir));

    // Destination
    rule.dstIp = std::string(tokens[5]);
    rule.dstPort = std::string(tokens[6]);

    return {};
}

// ── parseOptions() ──────────────────────────────────────────────────

std::expected<void, std::string> SnortRuleParser::parseOptions(
    std::string_view options, core::SnortRule& rule) const {

    auto tokens = splitOptions(options);
    for (const auto& token : tokens) {
        auto [key, value] = splitKeyValue(token);
        auto result = parseOption(key, value, rule);
        if (!result) {
            spdlog::debug("SnortRuleParser: skipping option '{}': {}",
                         key, result.error());
        }
    }
    return {};
}

// ── parseOption() ───────────────────────────────────────────────────

std::expected<void, std::string> SnortRuleParser::parseOption(
    std::string_view key, std::string_view value,
    core::SnortRule& rule) const {

    if (key == "msg") {
        rule.msg = std::string(unquote(value));
    } else if (key == "sid") {
        rule.sid = parseUint32(value);
    } else if (key == "rev") {
        rule.rev = parseUint32(value);
    } else if (key == "classtype") {
        rule.classtype = std::string(value);
    } else if (key == "priority") {
        rule.priority = parseInt(value, 3);
    } else if (key == "content") {
        rule.contents.push_back(parseContent(value));
    } else if (key == "pcre") {
        rule.pcres.push_back(parsePcre(value));
    } else if (key == "flow") {
        rule.flow = parseFlow(value);
    } else if (key == "flowbits") {
        rule.flowbits.push_back(parseFlowbits(value));
    } else if (key == "threshold" || key == "detection_filter") {
        rule.threshold = parseThreshold(value);
    } else if (key == "reference") {
        auto comma = value.find(',');
        if (comma != std::string_view::npos) {
            rule.references.emplace_back(
                std::string(trim(value.substr(0, comma))),
                std::string(trim(value.substr(comma + 1))));
        }
    } else if (key == "metadata") {
        // metadata: key value, key value, ...
        auto parts = std::string(value);
        std::istringstream ss(parts);
        std::string chunk;
        while (std::getline(ss, chunk, ',')) {
            auto trimmed = trim(chunk);
            auto space = trimmed.find(' ');
            if (space != std::string_view::npos) {
                rule.metadata.emplace_back(
                    std::string(trim(trimmed.substr(0, space))),
                    std::string(trim(trimmed.substr(space + 1))));
            }
        }
    }
    // Content modifiers (apply to last content option)
    else if (key == "nocase" && !rule.contents.empty()) {
        rule.contents.back().nocase = true;
    } else if (key == "offset" && !rule.contents.empty()) {
        rule.contents.back().offset = parseInt(value);
    } else if (key == "depth" && !rule.contents.empty()) {
        rule.contents.back().depth = parseInt(value);
    } else if (key == "distance" && !rule.contents.empty()) {
        rule.contents.back().distance = parseInt(value);
    } else if (key == "within" && !rule.contents.empty()) {
        rule.contents.back().within = parseInt(value);
    }
    // Unknown options are silently skipped.

    return {};
}

// ── Content / PCRE / Flow / Flowbits / Threshold parsers ────────────

core::SnortRule::ContentOption SnortRuleParser::parseContent(
    std::string_view value) const {
    core::SnortRule::ContentOption opt;

    // Check for negation.
    value = trim(value);
    if (!value.empty() && value[0] == '!') {
        opt.negated = true;
        value.remove_prefix(1);
        value = trim(value);
    }

    opt.pattern = decodePattern(value);
    return opt;
}

core::SnortRule::PcreOption SnortRuleParser::parsePcre(
    std::string_view value) const {
    core::SnortRule::PcreOption opt;

    value = trim(value);

    // Check negation.
    if (!value.empty() && value[0] == '!') {
        opt.negated = true;
        value.remove_prefix(1);
        value = trim(value);
    }

    // Remove surrounding quotes.
    value = unquote(value);

    // Format: /pattern/modifiers
    if (value.size() >= 2 && value[0] == '/') {
        auto lastSlash = value.rfind('/');
        if (lastSlash > 0) {
            opt.pattern = std::string(value.substr(1, lastSlash - 1));
            if (lastSlash + 1 < value.size()) {
                opt.modifiers = std::string(value.substr(lastSlash + 1));
                opt.relative = opt.modifiers.find('R') != std::string::npos;
            }
        }
    }

    return opt;
}

core::SnortRule::FlowOption SnortRuleParser::parseFlow(
    std::string_view value) const {
    core::SnortRule::FlowOption opt;

    // Comma-separated keywords: established, to_server, to_client, etc.
    std::string val(value);
    std::istringstream ss(val);
    std::string keyword;
    while (std::getline(ss, keyword, ',')) {
        auto kw = trim(keyword);
        if (kw == "established") opt.established = true;
        else if (kw == "stateless") opt.stateless = true;
        else if (kw == "to_server" || kw == "from_client")
            opt.direction = core::SnortRule::FlowOption::Direction::ToServer;
        else if (kw == "to_client" || kw == "from_server")
            opt.direction = core::SnortRule::FlowOption::Direction::ToClient;
    }

    return opt;
}

core::SnortRule::FlowbitsOption SnortRuleParser::parseFlowbits(
    std::string_view value) const {
    core::SnortRule::FlowbitsOption opt;

    auto comma = value.find(',');
    auto cmd = trim(value.substr(0, comma));

    if (cmd == "set") opt.command = core::SnortRule::FlowbitsOption::Command::Set;
    else if (cmd == "isset") opt.command = core::SnortRule::FlowbitsOption::Command::Isset;
    else if (cmd == "unset") opt.command = core::SnortRule::FlowbitsOption::Command::Unset;
    else if (cmd == "toggle") opt.command = core::SnortRule::FlowbitsOption::Command::Toggle;
    else if (cmd == "noalert") opt.command = core::SnortRule::FlowbitsOption::Command::Noalert;
    else if (cmd == "isnotset") opt.command = core::SnortRule::FlowbitsOption::Command::IsnotSet;

    if (comma != std::string_view::npos) {
        auto rest = trim(value.substr(comma + 1));
        auto dot = rest.find('.');
        if (dot != std::string_view::npos) {
            opt.group = std::string(trim(rest.substr(0, dot)));
            opt.name = std::string(trim(rest.substr(dot + 1)));
        } else {
            opt.name = std::string(rest);
        }
    }

    return opt;
}

core::SnortRule::ThresholdOption SnortRuleParser::parseThreshold(
    std::string_view value) const {
    core::SnortRule::ThresholdOption opt;

    // Format: type limit, track by_src, count 5, seconds 60
    std::string val(value);
    std::istringstream ss(val);
    std::string keyword;
    while (std::getline(ss, keyword, ',')) {
        auto kv = trim(keyword);
        auto space = kv.find(' ');
        if (space == std::string_view::npos) continue;
        auto k = trim(kv.substr(0, space));
        auto v = trim(kv.substr(space + 1));

        if (k == "type") {
            if (v == "limit") opt.type = core::SnortRule::ThresholdOption::Type::Limit;
            else if (v == "threshold") opt.type = core::SnortRule::ThresholdOption::Type::Threshold;
            else if (v == "both") opt.type = core::SnortRule::ThresholdOption::Type::Both;
        } else if (k == "track") {
            if (v == "by_src") opt.track = core::SnortRule::ThresholdOption::Track::BySrc;
            else if (v == "by_dst") opt.track = core::SnortRule::ThresholdOption::Track::ByDst;
        } else if (k == "count") {
            opt.count = parseInt(v, 1);
        } else if (k == "seconds") {
            opt.seconds = parseInt(v, 60);
        }
    }

    return opt;
}

// ── File / Directory parsing ────────────────────────────────────────

std::vector<core::SnortRule> SnortRuleParser::parseFile(
    const fs::path& path) const {

    stats_ = {};
    std::vector<core::SnortRule> rules;

    std::ifstream file(path);
    if (!file.is_open()) {
        spdlog::error("SnortRuleParser: cannot open '{}'", path.string());
        return rules;
    }

    std::string line;
    while (std::getline(file, line)) {
        ++stats_.totalLines;
        auto trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') {
            ++stats_.skippedComments;
            continue;
        }

        auto result = parse(trimmed);
        if (result) {
            rules.push_back(std::move(*result));
            ++stats_.parsedRules;
        } else {
            ++stats_.parseErrors;
        }
    }

    spdlog::info("SnortRuleParser: parsed '{}': {} rules, {} errors",
                 path.string(), stats_.parsedRules, stats_.parseErrors);
    return rules;
}

std::vector<core::SnortRule> SnortRuleParser::parseDirectory(
    const fs::path& dir) const {

    stats_ = {};
    std::vector<core::SnortRule> allRules;

    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        if (ext != ".rules" && ext != ".rule") continue;

        auto rules = parseFile(entry.path());
        allRules.insert(allRules.end(),
                        std::make_move_iterator(rules.begin()),
                        std::make_move_iterator(rules.end()));
    }

    return allRules;
}

const SnortRuleParser::ParseStats&
SnortRuleParser::lastStats() const noexcept {
    return stats_;
}

} // namespace nids::infra
