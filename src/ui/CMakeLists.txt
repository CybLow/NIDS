# src/ui/CMakeLists.txt
# Presentation layer — Qt6 widgets and user interaction.

add_library(nids_ui STATIC
    MainWindow.cpp
    PacketTableModel.cpp
    FlowTableModel.cpp
    DetectionDetailWidget.cpp
    WeightTuningDialog.cpp
    HexView.cpp
    FilterPanel.cpp
    dialogs/ServiceDialog.cpp
    resources.qrc
)

# Add ServerDashboard only if gRPC/server is available.
if(NIDS_BUILD_SERVER)
    target_sources(nids_ui PRIVATE ServerDashboard.cpp)
    target_link_libraries(nids_ui PRIVATE nids-client-lib nids_proto)
    target_compile_definitions(nids_ui PRIVATE NIDS_HAS_GRPC_CLIENT)
endif()

target_link_libraries(nids_ui
    PUBLIC
        nids_core
        nids_app
    PRIVATE
        Qt::Widgets
        Qt::Core
        Qt::Gui
)

nids_set_target_defaults(nids_ui)
