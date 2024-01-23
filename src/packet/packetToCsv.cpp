//
// Created by sim on 22/01/24.
//

#include <limits>
#include "../../include/packet/packetToCsv.h"

void pcapToCsv() {

#ifdef __linux__
    system("./../pcaptocsv/convert_pcap_csv.sh dump.pcap");
    process_csv();
    process_csv_scientific();
    read_and_process_csv();
#endif

}

void process_csv() {
    std::ifstream input_file("../pcaptocsv/csv/dump_ISCX.csv");
    std::ofstream output_file("tmpdump.csv");
    std::string line;

    // Skip the first line (header)
    std::getline(input_file, line);

    while (std::getline(input_file, line)) {
        std::istringstream iss(line);
        std::string token;
        std::vector<std::string> tokens;


        while (std::getline(iss, token, ',')) {
            tokens.push_back(token);
        }

        // Assuming the order of the columns is known and fixed
        for (int i = 0; i < tokens.size(); ++i) {
            if (i != 0 && i != 1 && i != 2 && i != 3 && i != 4 && i != 6 && i != tokens.size() - 1) {
                output_file << tokens[i];
                if (i < tokens.size() - 1) {
                    output_file << ",";
                }
            }
        }
        output_file << "\n";
    }

    input_file.close();
    output_file.close();
}

bool contains_exponent(const std::string& s) {
    return s.find('E') != std::string::npos || s.find('e') != std::string::npos;
}

std::string process_scientific_notation(const std::string& s) {
    std::stringstream ss(s);
    long double number;
    ss >> number; // Read the number in its complete precision

    std::ostringstream out;
    out << std::fixed << std::setprecision(std::numeric_limits<long double>::digits10) << number;

    std::string result = out.str();
    // Remove trailing zeros
    result.erase(result.find_last_not_of('0') + 1, std::string::npos);
    // Remove the decimal point if it is now at the end
    if (result.back() == '.') {
        result.pop_back();
    }
    return result;
}

void process_csv_scientific() {
    std::ifstream input_file("tmpdump.csv");
    std::ofstream output_file("finaldump.csv");
    std::string line;
    bool first_line = true;

    while (std::getline(input_file, line)) {
        if (first_line) {
            // Write the first line (header) as is
            output_file << line << std::endl;
            first_line = false;
        } else {
            std::istringstream iss(line);
            std::string token;
            bool first_token = true;
            while (std::getline(iss, token, ',')) {
                if (!first_token) {
                    output_file << ",";
                }
                if (contains_exponent(token)) {
                    output_file << process_scientific_notation(token);
                } else {
                    output_file << token;
                }
                first_token = false;
            }
            output_file << std::endl;
        }
    }

    input_file.close();
    output_file.close();
}

std::vector<std::string> process_line_to_vector(const std::string& line) {
    std::vector<std::string> result;
    std::stringstream ss(line);
    std::string cell;

    while (std::getline(ss, cell, ',')) {
        result.push_back(cell);
    }

    return result;
}

void read_and_process_csv() {
    std::ifstream file("finaldump.csv");
    std::string line;

    // Skip the first line (header)
    std::getline(file, line);

    while (std::getline(file, line)) {
        std::vector<std::string> line_vector = process_line_to_vector(line);
        for (const auto& value : line_vector) {
            std::cout << value << " ";
        }
        std::cout << std::endl;
    }
}