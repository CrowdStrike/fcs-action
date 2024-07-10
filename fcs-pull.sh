#!/usr/bin/env bash

# This script is used to pull the FCS CLI container image.
# Uses the falcon-container-sensor-pull.sh script to pull the image.

set -o errexit
set -o nounset
set -o pipefail

# Download the falcon-container-sensor-pull.sh script
curl -O https://raw.githubusercontent.com/CrowdStrike/falcon-scripts/main/bash/containers/falcon-container-sensor-pull/falcon-container-sensor-pull.sh
env
# Check if the version is provided
VERSION=${INPUT_VERSION:+"--version ${INPUT_VERSION}"}

output=$(bash falcon-container-sensor-pull.sh -u ${INPUT_FALCON_CLIENT_ID} -r ${INPUT_FALCON_REGION} -t fcs ${VERSION})

# Extract the image name from the output
image_name=$(echo "$output" | grep ^registry.crowdstrike.com/fcs | tail -n 1)

# Set the image name as an output for the next step to use
echo "FCS_IMAGE=$image_name" >> $GITHUB_OUTPUT
