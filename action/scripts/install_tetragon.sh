#!/bin/bash

set -e

curl -LO https://github.com/cilium/tetragon/releases/latest/download/tetragon-amd64.tar.gz
tar -xvf tetragon-amd64.tar.gz
cd tetragon-amd64/
sudo ./install.sh
cd ..
rm -rf tetragon-amd64.tar.gz tetragon-amd64
