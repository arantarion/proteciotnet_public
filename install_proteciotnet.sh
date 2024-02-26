#!/bin/bash

if [ $(id -u) -ne 0 ]; then
  echo -e "\e[31mThis script must be run as root\e[0m"
  exit 1

fi

if [ -f banner.txt ]; then
    cat banner.txt
else
    echo "ProtecIoTnet Installer"
fi

echo "Welcome to the installer script!"
echo "This script will guide you through the installation process."

echo "Updating your system"
#sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y

echo "Installing some dependencies"
#sudo apt install python3 python3-pip curl wget nmap binutils libjpeg62 graphviz wireshark pandoc python-usb python-crypto python-serial python-dev libgcrypt-dev

echo "Installing Medusa"
git clone https://github.com/jmk-foofus/medusa
cd medusa
./configure
make && make install
# sudo cp src/medusa  /usr/local/bin


echo "Installing custom crackle version"
git clone https://github.com/arantarion/crackle.git
cp crackle /usr/local/bin/

echo "Installing Sniffle"
git clone https://github.com/nccgroup/Sniffle.git


echo "Installing Killerbee"
git clone https://github.com/riverloopsec/killerbee.git
cd killerbee
python3 setup.py install


echo "Installing Django"
#pip3 install Django requests xmltodict


echo "Creating ProtecIoTnet Django Project"
django-admin startproject ProtecIoTnet


cd ProtecIoTnet
mkdir proteciotnet_server

echo "Copying source files to proteciotnet_server"
cp -r ../src/* proteciotnet_server/

echo "Running migrations"
python3 manage.py migrate

echo "Copying django setup files"
cp ../setup/* ./ProtecIoTnet

cd ..

echo "Creating python3 virtual environment"
python3 -m venv env

echo "Activating env"
source env/bin/activate

echo "Installind ProtecIoTnet dependencies"
pip3 install -r requirements.txt

echo "Deactivating env"
deactivate


cd /opt
mkdir xml
mkdir notes
mkdir ble
mkdir nmap/formatter
mkdir zigbee


ARCH=$(uname -m)
echo "Detected architecture: $ARCH"

case $ARCH in
    x86_64)
        DOWNLOAD_URL="https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.bullseye_amd64.deb"
        ;;
    arm*)
        DOWNLOAD_URL="https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.raspberrypi.bullseye_armhf.deb
        echo "ARM architecture detected. Make sure to specify the correct download URL for ARM."
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo "Downloading wkhtmltopdf from $DOWNLOAD_URL"
wget "$DOWNLOAD_URL"
ar -x *.deb data.tar.xz
mkdir wkhtmltox
tar -xvf data.tar.xz --strip-component=3 -C wkhtmltox 



echo "Installation process is complete. Make sure to add your paths to proteciotnet.config before running run_proteciotnet.sh"

exit 0
