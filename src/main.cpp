#include "../include/packet/PacketCapture.h"

#include "include/ui/ui.h"
#include <QApplication>

using namespace std;

int main(int argc, char *argv[]) {
    QCoreApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication app(argc, argv);

    qRegisterMetaType<PacketInfo>("PacketInfo");


    PacketCaptureUI window;
    window.show();
    return app.exec();
}
