# src/app/CMakeLists.txt
# Application layer — pure C++23 orchestration logic, no Qt dependency.

add_library(nids_app STATIC
    CaptureController.cpp
    AnalysisService.cpp
    FlowAnalysisWorker.cpp
    HeadlessCaptureRunner.cpp
    LiveDetectionPipeline.cpp
    HybridDetectionService.cpp
    PipelineFactory.cpp
    SinkChain.cpp
    OutputSinkFactory.cpp
    HuntEngine.cpp
    VerdictEngine.cpp
    BypassManager.cpp
    commands/CaptureCommands.cpp
)

target_link_libraries(nids_app
    PUBLIC
        nids_core
    PRIVATE
        nids_infra
        spdlog::spdlog
)

nids_set_target_defaults(nids_app)
