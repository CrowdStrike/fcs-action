#!/usr/bin/env bash

# This script is used to execute the FCS CLI tool with the provided arguments.
# Current context is executing the FCS CLI container.

validate_bool() {
    local value=$1
    value=$(echo "$value" | tr '[:upper:]' '[:lower:]')
    if [[ "$value" == "true" ]] || [[ "$value" == "false" ]]; then
        echo "$value"
    else
        echo "Invalid"
    fi
}

validate_path() {
    local path=$1
    # if the path does not start with git::, then let's test it exists
    if [[ ! "$path" =~ ^git:: ]]; then
        if [[ ! -e "$path" ]]; then
            echo "Path does not exist: $path"
            exit 1
        fi
    fi
}

# Validate required inputs
invalid=false
[[ -z ${INPUT_FALCON_CLIENT_ID} ]] && echo "Missing required input 'falcon-client-id'" && invalid=true
[[ -z ${FALCON_CLIENT_SECRET} ]] && echo "Missing required env variable 'FALCON_CLIENT_SECRET'" && invalid=true
[[ -z ${INPUT_FALCON_REGION} ]] && echo "Missing required input 'falcon-region'" && invalid=true
[[ -z ${INPUT_PATH} ]] && echo "Missing required input 'path'" && invalid=true
if [[ "$invalid" == "true" ]]; then
    exit 1
fi

# Validate the path
validate_path "${INPUT_PATH}" && PATH_PARAM="-p ${INPUT_PATH}"

# Set variable for client-secret (provided as a secret)
[[ -n "${FALCON_CLIENT_SECRET}" ]] && CLIENT_SECRET_PARAM="--client-secret ${FALCON_CLIENT_SECRET}"
# Set variables based on recieved inputs
[[ -n "${INPUT_FALCON_CLIENT_ID}" ]] && CLIENT_ID_PARAM="--client-id ${INPUT_FALCON_CLIENT_ID}"
[[ -n "${INPUT_FALCON_REGION}" ]] && FALCON_REGION_PARAM="--falcon-region ${INPUT_FALCON_REGION}"
[[ -n "${INPUT_CATEGORIES}" ]] && CATEGORIES_PARAM="--categories ${INPUT_CATEGORIES}"
[[ -n "${INPUT_CONFIG}" ]] && CONFIG_PARAM="-c ${INPUT_CONFIG}"
[[ -n "${INPUT_EXCLUDE_CATEGORIES}" ]] && EXCLUDE_CATEGORIES_PARAM="--exclude-categories ${INPUT_EXCLUDE_CATEGORIES}"
[[ -n "${INPUT_EXCLUDE_PATHS}" ]] && EXCLUDE_PATHS_PARAM="-e ${INPUT_EXCLUDE_PATHS}"
[[ -n "${INPUT_EXCLUDE_PLATFORMS}" ]] && EXCLUDE_PLATFORMS_PARAM="--exclude-platforms ${INPUT_EXCLUDE_PLATFORMS}"
[[ -n "${INPUT_EXCLUDE_SEVERITIES}" ]] && EXCLUDE_SEVERITIES_PARAM="--exclude-severities ${INPUT_EXCLUDE_SEVERITIES}"
[[ -n "${INPUT_FAIL_ON}" ]] && FAIL_ON_PARAM="--fail-on ${INPUT_FAIL_ON}"
[[ -n "${INPUT_OUTPUT_PATH}" ]] && OUTPUT_PATH_PARAM="-o ${INPUT_OUTPUT_PATH}"
[[ -n "${INPUT_PLATFORMS}" ]] && PLATFORMS_PARAM="--platforms ${INPUT_PLATFORMS}"
[[ -n "${INPUT_PROJECT_OWNERS}" ]] && PROJECT_OWNERS_PARAM="--project-owners ${INPUT_PROJECT_OWNERS}"
[[ -n "${INPUT_REPORT_FORMATS}" ]] && REPORT_FORMATS_PARAM="-f ${INPUT_REPORT_FORMATS}"
[[ -n "${INPUT_SEVERITIES}" ]] && SEVERITIES_PARAM="--severities ${INPUT_SEVERITIES}"
[[ -n "${INPUT_TIMEOUT}" ]] && TIMEOUT_PARAM="-t ${INPUT_TIMEOUT}"

# Boolean based values
DISABLE_SECRET_SCAN=$(validate_bool "${INPUT_DISABLE_SECRETS_SCAN}")
if [[ "$DISABLE_SECRET_SCAN" == "Invalid" ]]; then
    echo "Invalid value for 'disable-secrets-scan'. Should be 'true' or 'false'."
    exit 1
elif [[ "$DISABLE_SECRET_SCAN" == "true" ]]; then
    DISABLE_SECRET_SCAN_PARAM="--disable-secrets-scan '$DISABLE_SECRET_SCAN'"
fi

# Handle the upload-results
UPLOAD_RESULTS=$(validate_bool "${INPUT_UPLOAD_RESULTS}")
if [[ "$UPLOAD_RESULTS" == "Invalid" ]]; then
    echo "Invalid value for 'upload-results'. Should be 'true' or 'false'."
    exit 1
elif [[ "$UPLOAD_RESULTS" == "true" ]]; then
    UPLOAD_RESULTS_PARAM="--upload-results $CLIENT_ID_PARAM $CLIENT_SECRET_PARAM $FALCON_REGION_PARAM"
fi

# Set the arguments
# Only set the args if the value is not empty
ARGS_ARRAY=("$PATH_PARAM" "$CATEGORIES_PARAM" "$CONFIG_PARAM" "$EXCLUDE_CATEGORIES_PARAM" "$EXCLUDE_PATHS_PARAM" "$EXCLUDE_PLATFORMS_PARAM" "$EXCLUDE_SEVERITIES_PARAM" "$FAIL_ON_PARAM" "$OUTPUT_PATH_PARAM" "$PLATFORMS_PARAM" "$PROJECT_OWNERS_PARAM" "$REPORT_FORMATS_PARAM" "$SEVERITIES_PARAM" "$TIMEOUT_PARAM" "$DISABLE_SECRET_SCAN_PARAM" "$UPLOAD_RESULTS_PARAM")

# Filter out the empty values
ARGS_PARAM=""
for arg in "${ARGS_ARRAY[@]}"; do
    if [[ -n "$arg" ]]; then
        ARGS_PARAM="$ARGS_PARAM $arg"
    fi
done

FCS_IMAGE="$OUTPUT_FCS_IMAGE"
FCS_CLI_BIN="/opt/crowdstrike/bin/fcs"
DOCKER_COMMAND="docker run --rm --platform linux/amd64 -v $(pwd):/workdir -w /workdir --entrypoint $FCS_CLI_BIN $FCS_IMAGE"
# Execute the FCS CLI tool
echo "INFO: Executing FCS CLI tool with the following arguments:$ARGS_PARAM"
$DOCKER_COMMAND iac scan $ARGS_PARAM
EXIT_CODE=$?

echo "exit-code=$EXIT_CODE" >> "$GITHUB_OUTPUT"
