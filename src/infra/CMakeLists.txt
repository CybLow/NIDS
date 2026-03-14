# src/infra/CMakeLists.txt
# Infrastructure layer — platform-specific implementations.

add_library(nids_infra STATIC
    capture/PcapCapture.cpp
    analysis/OnnxAnalyzer.cpp
    analysis/AnalyzerFactory.cpp
    analysis/FeatureNormalizer.cpp
    config/ConfigLoader.cpp
    flow/NativeFlowExtractor.cpp
    threat/ThreatIntelProvider.cpp
    rules/HeuristicRuleEngine.cpp
    platform/SocketInit.cpp
)

target_link_libraries(nids_infra
    PUBLIC
        nids_core
        PCAP::PCAP
    PRIVATE
        Threads::Threads
        onnxruntime::onnxruntime
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        Qt::Core
)

target_compile_definitions(nids_infra PRIVATE NIDS_HAS_ONNX)

if(WIN32)
    target_link_libraries(nids_infra PRIVATE iphlpapi delayimp)
    # Delay-load npcap DLLs so tests that don't call pcap functions
    # can run without the npcap runtime installed.
    target_link_options(nids_infra PUBLIC
        /DELAYLOAD:wpcap.dll
        /DELAYLOAD:Packet.dll
    )
endif()

nids_set_target_defaults(nids_infra)
