#!/bin/bash

git clone https://github.com/angr/angr-dev ~/angr-dev
cd ~/angr-dev

./setup.sh -i -E syml
source `which virtualenvwrapper.sh`
workon syml

git clone https://github.com/angr/tracer.git
pip install -e ./tracer/

#git clone git@github.com:angr/trraces.git
#sudo apt-get install ccache cmake make g++-multilib gdb pkg-config coreutils python3-pexpect manpages-dev git ninja-build capnproto libcapnp-dev
#cd trraces/trraces/
#wget https://raw.githubusercontent.com/mozilla/rr/master/src/rr_trace.capnp
#cd ..
#pip install -e .

cd ~/syml2
cp syml/config/default.config.py syml/config/config.py
#pip install -r requirements.txt
pip install -e .
