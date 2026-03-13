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
