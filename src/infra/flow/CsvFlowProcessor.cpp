#include "infra/flow/CsvFlowProcessor.h"

#include <QProcess>
#include <QCoreApplication>

#include <fstream>
#include <sstream>
#include <iostream>
#include <cmath>
#include <iomanip>
#include <limits>
#include <filesystem>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;

namespace nids::infra {

bool CsvFlowProcessor::extractFlows(const std::string& pcapPath,
                                     const std::string& outputCsvPath) {
    std::string rawCsvPath = outputCsvPath + ".raw";
    std::string cleanedPath = outputCsvPath + ".cleaned";

    if (!runCicFlowMeter(pcapPath, rawCsvPath)) {
        return false;
    }

    if (!cleanCsv(rawCsvPath, cleanedPath)) {
        return false;
    }

    if (!normalizeScientificNotation(cleanedPath, outputCsvPath)) {
        return false;
    }

    std::error_code ec;
    fs::remove(rawCsvPath, ec);
    fs::remove(cleanedPath, ec);

    return true;
}

std::vector<std::vector<float>> CsvFlowProcessor::loadFeatures(const std::string& csvPath) {
    std::vector<std::vector<float>> result;
    std::ifstream file(csvPath);
    if (!file.is_open()) {
        std::cerr << "Error: Unable to open file " << csvPath << std::endl;
        return result;
    }

    std::string line;
    std::getline(file, line); // skip header

    while (std::getline(file, line)) {
        auto features = parseLine(line);
        if (!features.empty()) {
            result.push_back(std::move(features));
        }
    }

    return result;
}

bool CsvFlowProcessor::runCicFlowMeter(const std::string& pcapPath,
                                         const std::string& rawCsvPath) const {
#ifdef __linux__
    QProcess process;
    QString scriptPath = QCoreApplication::applicationDirPath() + "/../pcaptocsv/convert_pcap_csv.sh";
    process.start("bash", {scriptPath, QString::fromStdString(pcapPath)});
    if (!process.waitForFinished(300000)) { // 5 min timeout
        std::cerr << "CICFlowMeter timed out" << std::endl;
        return false;
    }

    std::string cicOutput = QCoreApplication::applicationDirPath().toStdString()
                            + "/../pcaptocsv/csv/dump_ISCX.csv";
    if (!fs::exists(cicOutput)) {
        std::cerr << "CICFlowMeter output not found: " << cicOutput << std::endl;
        return false;
    }

    std::error_code ec;
    fs::rename(cicOutput, rawCsvPath, ec);
    return !ec;
#else
    (void)pcapPath;
    (void)rawCsvPath;
    std::cerr << "CICFlowMeter not supported on this platform" << std::endl;
    return false;
#endif
}

bool CsvFlowProcessor::cleanCsv(const std::string& inputPath,
                                  const std::string& outputPath) const {
    std::ifstream input(inputPath);
    std::ofstream output(outputPath);
    if (!input.is_open() || !output.is_open()) return false;

    std::string line;
    std::getline(input, line); // skip header

    while (std::getline(input, line)) {
        std::istringstream iss(line);
        std::string token;
        std::vector<std::string> tokens;

        while (std::getline(iss, token, ',')) {
            tokens.push_back(token);
        }

        bool first = true;
        for (std::size_t i = 0; i < tokens.size(); ++i) {
            if (i != 0 && i != 1 && i != 2 && i != 3 && i != 4
                && i != 6 && i != tokens.size() - 1) {
                if (!first) output << ",";
                output << tokens[i];
                first = false;
            }
        }
        output << "\n";
    }

    return true;
}

bool CsvFlowProcessor::normalizeScientificNotation(const std::string& inputPath,
                                                     const std::string& outputPath) const {
    std::ifstream input(inputPath);
    std::ofstream output(outputPath);
    if (!input.is_open() || !output.is_open()) return false;

    std::string line;
    bool firstLine = true;

    while (std::getline(input, line)) {
        if (firstLine) {
            output << line << "\n";
            firstLine = false;
            continue;
        }

        std::istringstream iss(line);
        std::string token;
        bool firstToken = true;

        while (std::getline(iss, token, ',')) {
            if (!firstToken) output << ",";
            if (containsExponent(token)) {
                output << processScientificNotation(token);
            } else {
                output << token;
            }
            firstToken = false;
        }
        output << "\n";
    }

    return true;
}

std::vector<float> CsvFlowProcessor::parseLine(const std::string& line) const {
    std::vector<float> result;
    std::stringstream ss(line);
    std::string cell;

    while (std::getline(ss, cell, ',')) {
        try {
            bool isNumeric = !cell.empty() && std::all_of(cell.begin(), cell.end(),
                [](unsigned char c) { return std::isdigit(c) || c == '.' || c == '-'; });

            if (!isNumeric) {
                result.push_back(0.0f);
                continue;
            }

            result.push_back(std::stof(cell));
        } catch (const std::exception&) {
            result.push_back(0.0f);
        }
    }

    // Pad to 79 features if needed
    while (result.size() < 79) {
        result.push_back(0.0f);
    }

    return result;
}

bool CsvFlowProcessor::containsExponent(const std::string& s) {
    return s.find('E') != std::string::npos || s.find('e') != std::string::npos;
}

std::string CsvFlowProcessor::processScientificNotation(const std::string& s) {
    std::stringstream ss(s);
    long double number;
    ss >> number;

    std::ostringstream out;
    out << std::fixed << std::setprecision(std::numeric_limits<long double>::digits10) << number;

    std::string result = out.str();
    result.erase(result.find_last_not_of('0') + 1, std::string::npos);
    if (!result.empty() && result.back() == '.') {
        result.pop_back();
    }
    return result;
}

} // namespace nids::infra
