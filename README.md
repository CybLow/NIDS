# NIDS - Network Intrusion Detection System

## WARNING : AT THE MOMENT ONLY LINUX SYSTEM ARE SUPPORTED (due to CICFlowMeter and some library of pcap data extraction)

## Introduction
NIDS is an advanced Network Intrusion Detection System leveraging AI to monitor and analyze network traffic for potential threats. It integrates CICFlowMeter for packet data extraction and uses an AI model to detect and classify network attacks.

## Prerequisites
Ensure you have the following prerequisites installed:
- **CMake** [Version 3.15 or higher](https://gitlab.kitware.com/cmake/cmake)
- **Qt5** - [Qt5 GitHub Repository](https://github.com/qt/qt5)
- **libpcap** - [libpcap GitHub Repository](https://github.com/the-tcpdump-group/libpcap)
- **frugally-deep** - [frugally-deep GitHub Repository](https://github.com/Dobiasd/frugally-deep/)

For more info check [INSTALL.md](https://github.com/CybLow/NIDS/blob/main/INSTALL.md)

## Features
- **AI-Powered Attack Identification**: Utilizes AI to detect and classify network attacks.
- **Summary Report**: After packet capture a report are created for a summary analysis.
- **Application Detection**: Identifies applications generating network traffic.
- **BPF/Standard Filters**: Supports BPF and standard filters, with GUI for standard filters.
- **Raw Data Inspection**: View raw data of network requests.
- **Notification Controls**: Enable/disable notifications for report generation.

## Build && Installation
```bash
mkdir build && cd build
cmake ..
make
sudo ./NIDS
```

## Bug Reporting
Known issues include crashes during report generation/computing due to memory allocation errors. Report bugs with detailed information about the circumstances.

## To-Do
- **Restructuration**: Do some change in code structure to improve the code clarity. 
- **Windows Portability**: Adapt code for Windows compatibility.
- **Code Refactoring**: Improve code clarity and consistency.
- **YARA Rules and AI Integration**: Enhance detection with YARA rules and AI.
- **Email Notifications**: Implement email notifications for reports.
- **Live AI Detection**: Develop real-time AI detection.
- **Endpoint Network Isolation**: Implement real filtering for network endpoints.
- **Enhanced Raw Data Information**: Provide more details in Raw Data menu.
- **Security Menu Development**: Make the Security menu functional.
- **Deep Packet Inspection (DPI)**: Implement DPI for thorough packet analysis.
- **CICFlowMeter**: Implement in CPP for better execution without do some garbage (like the actual solution).

