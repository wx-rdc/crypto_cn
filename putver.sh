#!/bin/bash

## 发布版本

if [ $# -eq 0 ]; then
    echo "请输入版本号"
    exit 1
fi

version=$1

echo "发布版本: $version"

git tag -a $version -m "release $version"
git push origin $version