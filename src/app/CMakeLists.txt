# src/app/CMakeLists.txt
# Application layer — pure C++23 orchestration logic, no Qt dependency.

add_library(nids_app STATIC
    CaptureController.cpp
    AnalysisService.cpp
    FlowAnalysisWorker.cpp
    LiveDetectionPipeline.cpp
    HybridDetectionService.cpp
    ReportGenerator.cpp
)

target_link_libraries(nids_app
    PUBLIC
        nids_core
    PRIVATE
        spdlog::spdlog
)

nids_set_target_defaults(nids_app)
