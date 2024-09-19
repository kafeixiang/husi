#!/bin/bash
set -e

[[ -e "inited" ]] && exit 0

# Install gomobile
CGO_ENABLED=0 go install -v -trimpath -ldflags="-w -s" github.com/sagernet/gomobile/cmd/gobind@v0.1.4
CGO_ENABLED=0 go install -v -trimpath -ldflags="-w -s" github.com/sagernet/gomobile/cmd/gomobile@v0.1.4

gomobile init
touch inited
