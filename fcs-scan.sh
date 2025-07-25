#!/usr/bin/env bash
# This script is used to execute the FCS CLI tool with the provided arguments.
# Supports both IaC scanning and container image scanning.
# Current context is executing the FCS CLI container.

readonly FCS_CLI_BIN="${OUTPUT_FCS_BIN:-}"

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
    local scan_type="${INPUT_SCAN_TYPE:-iac}"
    
    if [[ "$scan_type" == "iac" ]]; then
        # Check if INPUT_PATH or INPUT_CONFIG has been supplied for IaC scanning.
        local path="${INPUT_PATH:-}"
        local config="${INPUT_CONFIG:-}"
        if [[ -z "$path" && -z "$config" ]]; then
            die "Either 'path' or 'config' input is required for IaC scanning."
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
    elif [[ "$scan_type" == "image" ]]; then
        # Check if INPUT_IMAGE has been supplied for image scanning.
        local image="${INPUT_IMAGE:-}"
        if [[ -z "$image" ]]; then
            die "The 'image' input is required for image scanning."
        fi
    else
        die "Invalid scan_type '$scan_type'. Must be 'iac' or 'image'."
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
            log "Missing required input/env variable '${input#INPUT_}'. Please see the actions's documentation for more details." "ERROR"
            invalid=true
        fi
    done

    [[ "$invalid" == "true" ]] && exit 1
}

set_parameters() {
    local -a params=()
    local scan_type="${INPUT_SCAN_TYPE:-iac}"
    
    if [[ "$scan_type" == "iac" ]]; then
        # IaC-specific parameters
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
            "POLICY_RULE:policy-rule"
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
            params+=("--disable-secrets-scan")
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

    elif [[ "$scan_type" == "image" ]]; then
        # Image-specific parameters
        local input_params=(
            "IMAGE:image"
            "SOCKET:socket"
            "PLATFORM:platform"
            "OUTPUT_PATH:output"
            "REPORT_FORMATS:format"
            "MINIMUM_SCORE:minimum-score"
            "MINIMUM_SEVERITY:minimum-severity"
            "MINIMUM_EXPRT:minimum-exprt"
            "EXCLUDE_VULNERABILITIES:exclude-vulnerabilities"
            "REPORT_SORT_BY:report-sort-by"
            "MINIMUM_DETECTION_SEVERITY:minimum-detection-severity"
            "TEMP_DIR:temp-dir"
        )

        for param in "${input_params[@]}"; do
            local input_var="INPUT_${param%%:*}"
            local param_name="${param#*:}"
            if [[ -n "${!input_var:-}" ]]; then
                params+=("--${param_name} ${!input_var}")
            fi
        done

        # Handle boolean parameters for image scanning
        local vulnerability_only
        vulnerability_only=$(validate_bool "${INPUT_VULNERABILITY_ONLY:-}")
        if [[ "$vulnerability_only" == "true" ]]; then
            params+=("--vulnerability-only")
        elif [[ "$vulnerability_only" == "Invalid" ]]; then
            die "Invalid value for 'vulnerability-only'. Should be 'true' or 'false'."
        fi

        local sbom_only
        sbom_only=$(validate_bool "${INPUT_SBOM_ONLY:-}")
        if [[ "$sbom_only" == "true" ]]; then
            params+=("--sbom-only")
        elif [[ "$sbom_only" == "Invalid" ]]; then
            die "Invalid value for 'sbom-only'. Should be 'true' or 'false'."
        fi

        local vuln_fixable_only
        vuln_fixable_only=$(validate_bool "${INPUT_VULN_FIXABLE_ONLY:-}")
        if [[ "$vuln_fixable_only" == "true" ]]; then
            params+=("--vuln-fixable-only")
        elif [[ "$vuln_fixable_only" == "Invalid" ]]; then
            die "Invalid value for 'vuln-fixable-only'. Should be 'true' or 'false'."
        fi

        local show_full_description
        show_full_description=$(validate_bool "${INPUT_SHOW_FULL_DESCRIPTION:-}")
        if [[ "$show_full_description" == "true" ]]; then
            params+=("--show-full-description")
        elif [[ "$show_full_description" == "Invalid" ]]; then
            die "Invalid value for 'show-full-description'. Should be 'true' or 'false'."
        fi

        local show_full_detection_details
        show_full_detection_details=$(validate_bool "${INPUT_SHOW_FULL_DETECTION_DETAILS:-}")
        if [[ "$show_full_detection_details" == "true" ]]; then
            params+=("--show-full-detection-details")
        elif [[ "$show_full_detection_details" == "Invalid" ]]; then
            die "Invalid value for 'show-full-detection-details'. Should be 'true' or 'false'."
        fi

        local no_color
        no_color=$(validate_bool "${INPUT_NO_COLOR:-}")
        if [[ "$no_color" == "true" ]]; then
            params+=("--no-color")
        elif [[ "$no_color" == "Invalid" ]]; then
            die "Invalid value for 'no-color'. Should be 'true' or 'false'."
        fi

        local upload_results
        upload_results=$(validate_bool "${INPUT_UPLOAD_RESULTS:-}")
        if [[ "$upload_results" == "true" ]]; then
            params+=("--upload --client-id ${INPUT_FALCON_CLIENT_ID} --client-secret ${FALCON_CLIENT_SECRET} --falcon-region ${INPUT_FALCON_REGION}")
        elif [[ "$upload_results" == "Invalid" ]]; then
            die "Invalid value for 'upload-results'. Should be 'true' or 'false'."
        fi
    fi

    echo "${params[@]}"
}

execute_fcs_cli() {
    local args="$1"
    local scan_type="${INPUT_SCAN_TYPE:-iac}"

    cd "$GITHUB_WORKSPACE" || die "Failed to change directory to $GITHUB_WORKSPACE"

    log "Executing FCS CLI tool with scan type '$scan_type' and arguments: $args"
    
    if [[ "$scan_type" == "iac" ]]; then
        $FCS_CLI_BIN iac scan $args
    elif [[ "$scan_type" == "image" ]]; then
        $FCS_CLI_BIN scan image $args
    else
        die "Invalid scan_type '$scan_type'. Must be 'iac' or 'image'."
    fi
    
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
