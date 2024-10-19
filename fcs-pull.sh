#!/usr/bin/env bash

# This script is used to pull the FCS CLI container image.
# Uses the falcon-container-sensor-pull.sh script to pull the image.

set -o errexit
set -o nounset
set -o pipefail

# Download the falcon-container-sensor-pull.sh script
curl -O https://raw.githubusercontent.com/CrowdStrike/falcon-scripts/main/bash/containers/falcon-container-sensor-pull/falcon-container-sensor-pull.sh

# Check if the version is provided
VERSION=${INPUT_VERSION:+"--version ${INPUT_VERSION}"}

output=$(bash falcon-container-sensor-pull.sh -u ${INPUT_FALCON_CLIENT_ID} -r ${INPUT_FALCON_REGION} -t fcs ${VERSION})

# Extract the image name from the output
image_name=$(echo "$output" | grep ^registry.crowdstrike.com/fcs | tail -n 1)

# Check if the image name is empty
if [ -z "$image_name" ]; then
    echo "Failed to get the image name."
    exit 1
fi

# TBD: For the container image, let's extract and copy the binary
FCS_BIN_PATH=/opt/crowdstrike/bin
# Make sure the directory exists
mkdir -p $FCS_BIN_PATH
id=$(docker create "$image_name")
docker cp $id:$FCS_BIN_PATH/fcs $FCS_BIN_PATH

# Ensure the binary exists
if [ ! -f $FCS_BIN_PATH/fcs ]; then
    echo "Failed to copy the FCS binary."
    exit 1
fi

# Set the bin path as an output
echo "::set-output name=FCS_BIN::$FCS_BIN_PATH/fcs"
