//
// Created by sim on 22/01/24.
//

#ifndef PACKETTOCSV_H
#define PACKETTOCSV_H
#include <pcap/pcap.h>
#include <stdlib.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <iostream>
#include <cmath>
#include <iomanip>
#include <fdeep/fdeep.hpp>
#include "../include/globals.h"

void pcapToCsv();

void process_csv();

bool contains_exponent(const std::string& s);

std::string process_scientific_notation(const std::string& s);

void process_csv_scientific();

std::vector<float> process_line_to_vector(const std::string& line);

void read_and_process_csv();

int findMaxPositionInTensors(const fdeep::tensors& tensors);

#endif //PACKETTOCSV_H
