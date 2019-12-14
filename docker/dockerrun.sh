#!/bin/bash
#
# This file is part of clr-boot-manager.
#
# Copyright © 2017-2018 Intel Corporation
#
# clr-boot-manager is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1
# of the License, or (at your option) any later version.
#
mkdir -p /build
cd /build

if [[ ! -d /source ]]; then
    echo "Missing source tree!" >&2
    exit 1
fi

# Copy all the files across to prevent contaminating the bind mount
cp -Ra /source/. /build

./scripts/run-test-suite.sh || exit 1
