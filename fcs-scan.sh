#!/usr/bin/env bash
# This script is used to execute the FCS CLI tool with the provided arguments.
# Supports both IaC scanning and container image scanning.
# Current context is executing the FCS CLI container.

readonly FCS_CLI_BIN="${OUTPUT_FCS_BIN:-}"

check_sarif_requested() {
    local report_formats="${INPUT_REPORT_FORMATS:-}"
    local output_path="${INPUT_OUTPUT_PATH:-}"

    # Check if sarif is in report_formats
    if [[ -n "${report_formats}" ]]; then
        if echo "${report_formats}" | grep -qw "sarif"; then
            echo "true"
            return
        fi
    fi

    # Check if output_path ends with .sarif
    if [[ -n "${output_path}" && "${output_path}" == *.sarif ]]; then
        echo "true"
        return
    fi
}

prepare_report_formats_for_cli() {
    local report_formats="${INPUT_REPORT_FORMATS:-}"

    # If sarif is requested, replace it with json for CLI execution
    if echo "${report_formats}" | grep -qw "sarif"; then
        # Replace 'sarif' with 'json', handle various combinations
        # shellcheck disable=SC2001
        report_formats=$(echo "${report_formats}" | sed 's/sarif/json/g')
        # Remove duplicate 'json' entries if they exist
        report_formats=$(echo "${report_formats}" | tr ',' '\n' | sort -u | grep -v '^$' | tr '\n' ',' | sed 's/,$//')
    fi

    echo "${report_formats}"
}

convert_json_to_sarif() {
    local output_path

    if [ "$INPUT_SCAN_TYPE" = "iac" ]; then
        output_path="${INPUT_OUTPUT_PATH}"
    elif [ "$INPUT_SCAN_TYPE" = "image" ] && [ "$INPUT_OUTPUT_PATH" ]; then
        output_path="${INPUT_OUTPUT_PATH}"
    else
        output_path="$HOME/.crowdstrike/image_assessment/reports/"
    fi

    log "convert_json_to_sarif: Looking for JSON files in: $output_path"

    # Look for all .json files - handle both file and directory paths
    local all_json_files
    if [[ -f "$output_path" ]]; then
        # Handle single file case (can be .json or .sarif containing JSON content)
        all_json_files="$output_path"
        if [[ "$output_path" == *.sarif ]]; then
            log "convert_json_to_sarif: Processing file with .sarif extension containing JSON: $output_path"
        else
            log "convert_json_to_sarif: Processing single JSON file: $output_path"
        fi
    elif [[ -d "$output_path" ]]; then
        # Handle directory case
        all_json_files=$(find "$output_path" -name "*.json" 2>/dev/null)
        log "convert_json_to_sarif: Searching directory for JSON files"
    else
        # For image scans, try adjusting .sarif to .json if the original path doesn't exist
        if [[ "$INPUT_SCAN_TYPE" = "image" && "$output_path" == *.sarif ]]; then
            local json_path="${output_path%.sarif}.json"
            if [[ -f "$json_path" ]]; then
                output_path="$json_path"
                all_json_files="$output_path"
                log "convert_json_to_sarif: Found JSON file at adjusted path: $output_path"
            else
                all_json_files=""
                log "convert_json_to_sarif: Neither original nor adjusted path exists: $output_path" "WARN"
            fi
        else
            # Path doesn't exist or is not a file/directory
            all_json_files=""
            log "convert_json_to_sarif: Path does not exist or is not a file/directory: $output_path" "WARN"
        fi
    fi

    if [[ -n "$all_json_files" ]]; then
        log "convert_json_to_sarif: Found JSON files: $all_json_files"
        local success_count=0
        local total_count=0

        while IFS= read -r json_file; do
            if [[ -n "$json_file" ]]; then
                ((total_count++))

                # Generate SARIF filename - handle both .json and .sarif extensions
                local sarif_file
                if [[ "$json_file" == *.sarif ]]; then
                    # File already has .sarif extension (contains JSON content)
                    sarif_file="$json_file"
                    log "convert_json_to_sarif: File already has .sarif extension, will overwrite with SARIF content: $sarif_file"
                else
                    # Standard case: .json extension becomes .sarif
                    sarif_file="${json_file%.json}.sarif"
                fi

                log "convert_json_to_sarif: Converting $json_file to $sarif_file"

                # Use the Python converter
                if python3 "$GITHUB_ACTION_PATH/json_to_sarif_converter.py" "$json_file" "$sarif_file" 2>/dev/null; then
                    ((success_count++))
                    log "convert_json_to_sarif: Successfully converted $json_file to $sarif_file"
                else
                    log "convert_json_to_sarif: Failed to convert $json_file" "ERROR"
                fi
            fi
        done <<< "$all_json_files"

        log "convert_json_to_sarif: Successfully converted $success_count out of $total_count JSON files to SARIF"
    else
        log "convert_json_to_sarif: No JSON files found in $output_path" "WARN"
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
        "") echo "false" ;;  # Treat empty string as false
        *) echo "Invalid" ;;
    esac
}

path_exists() {
    local path="$1"
    [[ "$path" =~ ^git:: ]] || [[ -e "$path" ]] || die "Path/file does not exist: $path"
}

ensure_output_directory() {
    local output_path="$1"

    # Skip if no output path provided
    if [[ -z "$output_path" ]]; then
        return
    fi

    # Determine if this is a directory or file path
    local dir_path
    if [[ "$output_path" == */ ]] || [[ ! "$output_path" =~ \. ]]; then
        # Ends with / or has no extension - treat as directory
        dir_path="$output_path"
    else
        # Has extension - get parent directory
        dir_path=$(dirname "$output_path")
    fi

    # Create directory if it doesn't exist
    if [[ ! -d "$dir_path" ]]; then
        log "Creating output directory: $dir_path"
        mkdir -p "$dir_path" || die "Failed to create output directory: $dir_path"
    fi
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

        # If OUTPUT_PATH is provided for image scanning, validate file extension
        local output_path="${INPUT_OUTPUT_PATH:-}"
        if [[ -n "$output_path" ]]; then
            case "$output_path" in
                *.cdx.json|*.sarif|*.json)
                    # Valid extension
                    ;;
                *)
                    die "Invalid output path for image scanning: '$output_path'. Path must end with .json, .sarif, or .cdx.json extension."
                    ;;
            esac
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
                # Special handling for output path - ensure directory exists
                if [[ "$param_name" == "output-path" ]]; then
                    ensure_output_directory "${!input_var}"
                    params+=("--${param_name} ${!input_var}")
                # Special handling for report formats - replace sarif with json if needed
                elif [[ "$param_name" == "report-formats" ]]; then
                    local prepared_formats
                    prepared_formats=$(prepare_report_formats_for_cli)
                    params+=("--${param_name} ${prepared_formats}")
                else
                    params+=("--${param_name} ${!input_var}")
                fi
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
            "TIMEOUT:timeout"
        )

        for param in "${input_params[@]}"; do
            local input_var="INPUT_${param%%:*}"
            local param_name="${param#*:}"
            if [[ -n "${!input_var:-}" ]]; then
                # Special handling for report formats - replace sarif with json if needed
                if [[ "$param_name" == "format" ]]; then
                    local prepared_formats
                    prepared_formats=$(prepare_report_formats_for_cli)
                    params+=("--${param_name} ${prepared_formats}")
                elif [[ "$param_name" == "output" ]]; then
                    # Special handling for output path - change .sarif to .json to ensure JSON generation
                    local output_value="${!input_var}"
                    if [[ "$output_value" == *.sarif ]]; then
                        output_value="${output_value%.sarif}.json"
                        log "Output path changed from ${!input_var} to ${output_value} to ensure JSON generation"
                    fi
                    params+=("--${param_name} ${output_value}")
                else
                    params+=("--${param_name} ${!input_var}")
                fi
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
        # shellcheck disable=SC2086
        $FCS_CLI_BIN scan iac $args
    elif [[ "$scan_type" == "image" ]]; then
        # shellcheck disable=SC2086
        $FCS_CLI_BIN scan image $INPUT_IMAGE $args
    else
        die "Invalid scan_type '$scan_type'. Must be 'iac' or 'image'."
    fi

    local exit_code=$?
    echo "exit-code=$exit_code" >> "$GITHUB_OUTPUT"
}

main() {
    export FCS_CLIENT_ID="$INPUT_FALCON_CLIENT_ID"
    export FCS_CLIENT_SECRET="$FALCON_CLIENT_SECRET"
    validate_required_inputs
    validate_path
    local args
    args=$(set_parameters)
    execute_fcs_cli "$args"

    # If SARIF format was requested, convert JSON output to SARIF using Python converter
    IS_SARIF=$(check_sarif_requested)
    if [[ "${IS_SARIF}" == "true" ]]; then
        convert_json_to_sarif
    fi
}

main
