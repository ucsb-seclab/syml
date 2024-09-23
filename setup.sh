#!/bin/bash

git clone https://github.com/angr/angr-dev angr-dev

pushd angr-dev

./setup.sh -i -E syml
source `which virtualenvwrapper.sh`
workon syml

git clone https://github.com/angr/tracer.git tracer
pip install -e ./tracer

# archr should come with angr-dev
# git clone https://github.com/angr/archr.git archr
# pip install -e ./archr

#git clone git@github.com:angr/trraces.git
#sudo apt-get install ccache cmake make g++-multilib gdb pkg-config coreutils python3-pexpect manpages-dev git ninja-build capnproto libcapnp-dev
#cd trraces/trraces/
#wget https://raw.githubusercontent.com/mozilla/rr/master/src/rr_trace.capnp
#cd ..
#pip install -e .

popd

cp syml/config/default.config.py syml/config/config.py
#pip install -r requirements.txt
pip install -e .
