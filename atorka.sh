#!/bin/bash

VERSION=$(lsb_release -a)

KALI='Kali'

if [[ "$VERSION" == *"$KALI"* ]];
then
    sudo apt install python3.6
    sudo apt install python3-pip
    sudo apt install wget
    cd /home/kali/Desktop
    #wget https://raw.githubusercontent.com/binexisHATT/Botnet-Command-Control/master/scripts/net/cc.py - change this to our cc.py
    chmod +x cc.py
    ./cc.py
fi

