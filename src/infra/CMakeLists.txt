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
    platform/DelayLoadHook.cpp
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
        Qt::Core
)

target_compile_definitions(nids_infra PRIVATE NIDS_HAS_ONNX)

if(WIN32)
    # Delay-load pcap DLLs: PcapPlusPlus links against npcap SDK but CI uses
    # WinPcap runtime (which lacks npcap-specific exports). DELAYLOAD resolves
    # each function lazily, so standard pcap functions (pcap_open_offline, etc.)
    # resolve against WinPcap while npcap-only functions are never called.
    target_link_libraries(nids_infra PRIVATE delayimp)
    target_link_options(nids_infra PUBLIC
        /DELAYLOAD:wpcap.dll
        /DELAYLOAD:Packet.dll
    )
endif()

nids_set_target_defaults(nids_infra)
