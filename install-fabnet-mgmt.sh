#!/bin/bash

if [ -z "$1" ]
then
    url="https://github.com/fabregas/fabnet_mgmt/archive/master.zip"
else
    url=$1
fi

echo "Installing package from $url ..."

PYTHONPATH="/opt/blik/fabnet/packages" easy_install --install-dir=/opt/blik/fabnet/packages \
        --prefix=/opt/blik/fabnet  --record=/opt/blik/fabnet/mgmt_package_files.lst $url

