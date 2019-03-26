#!/bin/bash
set -e
build_folder=$1
timeout=$2
test_folder=$3
shift 2
arguments=$@
source ${build_folder}/activate.sh
#sudo prior to timeout. in case its needed inside
sudo echo "sudo trigger"
timeout -s 2 $timeout python2 -u $test_folder/test.py $arguments || echo "Test timed out"; sleep 1
