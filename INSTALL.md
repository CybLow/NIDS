## CMake INSTALLATION :
```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install cmake
```

## Qt5 INSTALLATION :
```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools
```

## libpcap INSTALLATION :
```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install libpcap-dev
```

## frugally-deep INSTALLATION :
```bash
git clone -b 'v0.2.22' --single-branch --depth 1 https://github.com/Dobiasd/FunctionalPlus
cd FunctionalPlus
mkdir -p build && cd build
cmake ..
make && sudo make install
cd ../..

git clone -b '3.4.0' --single-branch --depth 1 https://gitlab.com/libeigen/eigen.git
cd eigen
mkdir -p build && cd build
cmake ..
make && sudo make install
sudo ln -s /usr/local/include/eigen3/Eigen /usr/local/include/Eigen
cd ../..

git clone -b 'v3.11.3' --single-branch --depth 1 https://github.com/nlohmann/json
cd json
mkdir -p build && cd build
cmake -DJSON_BuildTests=OFF ..
make && sudo make install
cd ../..

git clone https://github.com/Dobiasd/frugally-deep
cd frugally-deep
mkdir -p build && cd build
cmake ..
make && sudo make install
cd ../..
```
