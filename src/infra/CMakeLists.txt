# src/infra/CMakeLists.txt
# Infrastructure layer — platform-specific implementations.

add_library(nids_infra STATIC
    capture/PcapCapture.cpp
    capture/PcapCaptureWorker.cpp
    analysis/OnnxAnalyzer.cpp
    analysis/AnalyzerFactory.cpp
    analysis/FeatureNormalizer.cpp
    config/ConfigLoader.cpp
    flow/NativeFlowExtractor.cpp
    threat/ThreatIntelProvider.cpp
    rules/HeuristicRuleEngine.cpp
    output/ConsoleAlertSink.cpp
    parsing/PacketParser.cpp
    platform/SocketInit.cpp
)

target_link_libraries(nids_infra
    PUBLIC
        nids_core
        PcapPlusPlus::PcapPlusPlus
    PRIVATE
        Threads::Threads
        onnxruntime::onnxruntime
        nlohmann_json::nlohmann_json
        spdlog::spdlog
)

target_compile_definitions(nids_infra PRIVATE NIDS_HAS_ONNX)

if(WIN32)
    # Delay-load npcap DLLs so test discovery and non-pcap tests can run
    # without npcap runtime installed. Pcap-dependent tests use GTEST_SKIP
    # on Windows CI (PcapPlusPlus uses pcap_open_offline_with_tstamp_precision
    # which requires npcap; WinPcap is too old). To run all tests on Windows,
    # install npcap (free: npcap.com, or OEM for CI: fyodor@nmap.org).
    target_link_libraries(nids_infra PRIVATE delayimp)
    target_link_options(nids_infra PUBLIC
        /DELAYLOAD:wpcap.dll
        /DELAYLOAD:Packet.dll
    )
endif()

nids_set_target_defaults(nids_infra)
