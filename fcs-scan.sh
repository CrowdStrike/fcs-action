#!/usr/bin/env bash
# This script is used to execute the FCS CLI tool with the provided arguments.
# Current context is executing the FCS CLI container.

readonly FCS_CLI_BIN="/opt/crowdstrike/bin/fcs"
readonly FCS_IMAGE="${OUTPUT_FCS_IMAGE:-}"

# TODO: Remove these functions when upstream fix is in place
check_sarif() {
    local report_formats="${INPUT_REPORT_FORMATS:-}"
    # If sarif is in report_formats, set variable
    if [[ -n "${report_formats}" ]]; then
        if echo "${report_formats}" | grep -qw "sarif"; then
            echo "true"
        fi
    fi
}

fix_sarif() {
    local file output_path
    output_path="${INPUT_OUTPUT_PATH}"
    file=$(find "$output_path" -name "*-scan-results.sarif")
    if [[ -n "$file" ]]; then
        jq 'if .runs[0].tool.driver.informationUri == "" then
            .runs[0].tool.driver.informationUri = "https://crowdstrike.com"
            else
                .
            end' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
    fi
}

log() {
    local log_level=${2:-INFO}
    echo "[$(date +'%Y-%m-%dT%H:%M:%S')] $log_level: $1" >&2
}

die() {
    log "$1" "ERROR"
    exit 1
}

validate_bool() {
    local value
    value=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    case "$value" in
        true|false) echo "$value" ;;
        *) echo "Invalid" ;;
    esac
}

path_exists() {
    local path="$1"
    [[ "$path" =~ ^git:: ]] || [[ -e "$path" ]] || die "Path/file does not exist: $path"
}

validate_path() {
    # Check if INPUT_PATH or INPUT_CONFIG has been supplied.
    local path="${INPUT_PATH:-}"
    local config="${INPUT_CONFIG:-}"
    if [[ -z "$path" && -z "$config" ]]; then
        die "Either 'path' or 'config' input is required."
    fi

    # Path takes precedence over config. If path is supplied, validate it.
    if [[ -n "$path" ]]; then
        path_exists "$path"
    else
        # If config is supplied, verify "path": exists in the file and get the value and validate it.
        if [[ -n "$config" ]]; then
            local config_path
            config_path=$(jq -r '.path' "$config")
            [[ -n "$config_path" ]] || die "Invalid 'config' input. Missing 'path' key."
            path_exists "$config_path"
        fi
    fi

}

validate_required_inputs() {
    local invalid=false
    local -a required_inputs=(
        "INPUT_FALCON_CLIENT_ID"
        "FALCON_CLIENT_SECRET"
        "INPUT_FALCON_REGION"
    )

    for input in "${required_inputs[@]}"; do
        if [[ -z "${!input:-}" ]]; then
            log "Missing required input/env variable '${input#INPUT_}'"
            invalid=true
        fi
    done

    [[ "$invalid" == "true" ]] && exit 1
}

set_parameters() {
    local -a params=()
    local input_params=(
        "PATH:path"
        "CATEGORIES:categories"
        "CONFIG:config"
        "EXCLUDE_CATEGORIES:exclude-categories"
        "EXCLUDE_PATHS:exclude-paths"
        "EXCLUDE_PLATFORMS:exclude-platforms"
        "EXCLUDE_SEVERITIES:exclude-severities"
        "FAIL_ON:fail-on"
        "OUTPUT_PATH:output-path"
        "PLATFORMS:platforms"
        "PROJECT_OWNERS:project-owners"
        "REPORT_FORMATS:report-formats"
        "SEVERITIES:severities"
        "TIMEOUT:timeout"
    )

    for param in "${input_params[@]}"; do
        local input_var="INPUT_${param%%:*}"
        local param_name="${param#*:}"
        if [[ -n "${!input_var:-}" ]]; then
            params+=("--${param_name} ${!input_var}")
        fi
    done

    local disable_secret_scan
    disable_secret_scan=$(validate_bool "${INPUT_DISABLE_SECRETS_SCAN:-}")
    if [[ "$disable_secret_scan" == "true" ]]; then
        params+=("--disable-secrets-scan true")
    elif [[ "$disable_secret_scan" == "Invalid" ]]; then
        die "Invalid value for 'disable-secrets-scan'. Should be 'true' or 'false'."
    fi

    local upload_results
    upload_results=$(validate_bool "${INPUT_UPLOAD_RESULTS:-}")
    if [[ "$upload_results" == "true" ]]; then
        params+=("--upload-results --client-id ${INPUT_FALCON_CLIENT_ID} --client-secret ${FALCON_CLIENT_SECRET} --falcon-region ${INPUT_FALCON_REGION}")
    elif [[ "$upload_results" == "Invalid" ]]; then
        die "Invalid value for 'upload-results'. Should be 'true' or 'false'."
    fi

    echo "${params[@]}"
}

execute_fcs_cli() {
    local args="$1"
    local fcs_image="${FCS_IMAGE}"
    [[ -n "$fcs_image" ]] || die "OUTPUT_FCS_IMAGE is not set. Ensure the FCS CLI container image was pulled successfully."

    setfacl -m u:999:rwx "$GITHUB_WORKSPACE" || die "Failed to set permissions for container user."
    cd "$GITHUB_WORKSPACE" || die "Failed to change directory to $GITHUB_WORKSPACE"

    local docker_command
    docker_command="docker run --rm --platform linux/amd64 -v $(pwd):/workdir -w /workdir --entrypoint $FCS_CLI_BIN $fcs_image"

    log "Executing FCS CLI tool with the following arguments: $args"
    $docker_command iac scan $args
    local exit_code=$?

    echo "exit-code=$exit_code" >> "$GITHUB_OUTPUT"
}

main() {
    validate_required_inputs
    validate_path
    local args
    args=$(set_parameters)
    execute_fcs_cli "$args"
    # TODO: Remove this when upstream fix is in place
    # if sarif format has been requested, then fix informationUri
    IS_SARIF=$(check_sarif)
    if [[ "${IS_SARIF}" == "true" ]]; then
        fix_sarif
    fi
}

main
