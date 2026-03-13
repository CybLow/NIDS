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
    PRIVATE
        PCAP::PCAP
        Threads::Threads
        onnxruntime::onnxruntime
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        Qt::Core
)

target_compile_definitions(nids_infra PRIVATE NIDS_HAS_ONNX)

nids_set_target_defaults(nids_infra)
