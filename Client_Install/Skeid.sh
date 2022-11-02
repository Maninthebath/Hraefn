#!/bin/bash

VERSION=$(lsb_release -a)

KALI='Kali'

if [[ "$VERSION" == *"$KALI"* ]];
then
    sudo apt install python3.6
    sudo apt install python3-pip
    sudo apt install wget
    cd /home/kali/Desktop
    wget https://github.com/Maninthebath/Hraefn/raw/main/Client_Install/Urd.py
    chmod +x Urd.py
    ./Urd.py
fi
