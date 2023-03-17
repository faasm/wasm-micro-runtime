#!/bin/bash

set -e

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]:-${(%):-%x}}" )" >/dev/null 2>&1 && pwd )"
PROJ_ROOT="${THIS_DIR}/.."
BUILD_DIR="${PROJ_ROOT}/build"

pushd ${PROJ_ROOT} >> /dev/null

# Install Conan if not available
if ! command -v conan &> /dev/null; then
    pip3 install -U conan
fi

if [[ "$1" == "--clean" ]]; then
    rm -rf ${BUILD_DIR}
fi

mkdir -p ${BUILD_DIR}

# Install project build dependencies using Conan
conan install \
    ${PROJ_ROOT} \
    --profile ${PROJ_ROOT}/conan_profile.txt \
    --output-folder=${BUILD_DIR} \
    --build=missing

pushd ${BUILD_DIR} >> /dev/null

# Run CMake and build
cmake \
    -GNinja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=/usr/bin/clang-14 \
    -DCMAKE_CXX_COMPILER=/usr/bin/clang++-14 \
    -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake \
    ..
cmake --build .

popd >> /dev/null
popd >> /dev/null
