#include "../include/packet/PacketCapture.h"
#include "../include/utils/NetworkInterfaceSelector.h"
#include <iostream>

using namespace std;

/*int main() {
    try {
        NetworkInterfaceSelector interfaceSelector;
        auto selectedInterface = interfaceSelector.SelectInterface();

        PacketCapture capture(selectedInterface);
        capture.Initialize();
        capture.StartCapture();

        cout << "Press Enter to stop capture..." << std::endl;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        cin.get();

        capture.StopCapture(); // Debugging: Check if this function is called

        cout << "Capture stopped. Waiting for the capture thread..." << endl;

    }
    catch (const std::exception& e) {
        std::cerr << "Erreur: " << e.what() << std::endl;
        return 1;
    }

    cout << "Program ending" << endl;  // Confirmer la fin du programme
    return 0;
}*/