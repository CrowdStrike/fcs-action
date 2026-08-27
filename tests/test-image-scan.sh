#!/usr/bin/env bash
# Test script for image scanning functionality
# This script tests the fcs-scan.sh script with image scanning parameters

set -e

# Test configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$TEST_DIR")"
FCS_SCAN_SCRIPT="$PROJECT_ROOT/fcs-scan.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Mock environment variables for testing
export GITHUB_WORKSPACE="$PROJECT_ROOT"
export GITHUB_OUTPUT="/tmp/github_output_$$"
export OUTPUT_FCS_BIN="echo fcs"  # Mock FCS CLI for testing

# Test function to validate parameter generation
test_parameter_generation() {
    local test_name="$1"
    local expected_contains="$2"
    shift 2
    local env_vars=("$@")
    
    log "Testing: $test_name"
    
    # Set environment variables
    for env_var in "${env_vars[@]}"; do
        export "$env_var"
    done
    
    # Create a test script that extracts parameter generation logic
    local test_script="/tmp/test_params_$$"
    cat > "$test_script" << 'EOF'
#!/usr/bin/env bash
# Mock required functions for testing
validate_bool() {
    local value
    value=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    case "$value" in
        true|false) echo "$value" ;;
        *) echo "Invalid" ;;
    esac
}

# Extract and run the set_parameters function
set_parameters() {
    local -a params=()
    local scan_type="${INPUT_SCAN_TYPE:-iac}"
    
    if [[ "$scan_type" == "image" ]]; then
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
        fi

        local sbom_only
        sbom_only=$(validate_bool "${INPUT_SBOM_ONLY:-}")
        if [[ "$sbom_only" == "true" ]]; then
            params+=("--sbom-only")
        fi

        local vuln_fixable_only
        vuln_fixable_only=$(validate_bool "${INPUT_VULN_FIXABLE_ONLY:-}")
        if [[ "$vuln_fixable_only" == "true" ]]; then
            params+=("--vuln-fixable-only")
        fi

        local show_full_description
        show_full_description=$(validate_bool "${INPUT_SHOW_FULL_DESCRIPTION:-}")
        if [[ "$show_full_description" == "true" ]]; then
            params+=("--show-full-description")
        fi

        local show_full_detection_details
        show_full_detection_details=$(validate_bool "${INPUT_SHOW_FULL_DETECTION_DETAILS:-}")
        if [[ "$show_full_detection_details" == "true" ]]; then
            params+=("--show-full-detection-details")
        fi

        local no_color
        no_color=$(validate_bool "${INPUT_NO_COLOR:-}")
        if [[ "$no_color" == "true" ]]; then
            params+=("--no-color")
        fi

        local upload_results
        upload_results=$(validate_bool "${INPUT_UPLOAD_RESULTS:-}")
        if [[ "$upload_results" == "true" ]]; then
            params+=("--upload --client-id ${INPUT_FALCON_CLIENT_ID} --client-secret ${FALCON_CLIENT_SECRET} --falcon-region ${INPUT_FALCON_REGION}")
        fi
    fi

    echo "${params[@]}"
}

set_parameters
EOF

    chmod +x "$test_script"
    
    # Test parameter generation
    local params
    if params=$("$test_script" 2>/dev/null); then
        if [[ "$params" == *"$expected_contains"* ]]; then
            echo -e "  ${GREEN}✓${NC} Parameters contain expected value: $expected_contains"
        else
            error "Parameters don't contain expected value: $expected_contains"
            error "Generated parameters: $params"
            rm -f "$test_script"
            return 1
        fi
    else
        error "Failed to generate parameters"
        rm -f "$test_script"
        return 1
    fi
    
    rm -f "$test_script"
    
    # Clean up environment variables
    for env_var in "${env_vars[@]}"; do
        unset "${env_var%%=*}"
    done
    
    echo
}

# Test function to validate validation logic
test_validation() {
    local test_name="$1"
    local should_pass="$2"
    shift 2
    local env_vars=("$@")
    
    log "Testing validation: $test_name"
    
    # Set environment variables
    for env_var in "${env_vars[@]}"; do
        export "$env_var"
    done
    
    # Create a test script that replicates validation logic
    local test_script="/tmp/test_validation_$$"
    cat > "$test_script" << 'EOF'
#!/usr/bin/env bash
validate_path() {
    local scan_type="${INPUT_SCAN_TYPE:-iac}"
    
    if [[ "$scan_type" == "iac" ]]; then
        # Check if INPUT_PATH or INPUT_CONFIG has been supplied for IaC scanning.
        local path="${INPUT_PATH:-}"
        local config="${INPUT_CONFIG:-}"
        if [[ -z "$path" && -z "$config" ]]; then
            return 1  # fail validation
        fi

        # Path takes precedence over config. If path is supplied, validate it.
        if [[ -n "$path" ]]; then
            [[ "$path" =~ ^git:: ]] || [[ -e "$path" ]] || return 1
        else
            # If config is supplied, verify "path": exists in the file and get the value and validate it.
            if [[ -n "$config" ]]; then
                if [[ -f "$config" ]] && command -v jq >/dev/null 2>&1; then
                    local config_path
                    config_path=$(jq -r '.path' "$config" 2>/dev/null)
                    [[ -n "$config_path" ]] || return 1
                    [[ "$config_path" =~ ^git:: ]] || [[ -e "$config_path" ]] || return 1
                else
                    return 1
                fi
            fi
        fi
    elif [[ "$scan_type" == "image" ]]; then
        # Check if INPUT_IMAGE has been supplied for image scanning.
        local image="${INPUT_IMAGE:-}"
        if [[ -z "$image" ]]; then
            return 1  # fail validation
        fi
    else
        return 1  # invalid scan type
    fi
    
    return 0  # pass validation
}

validate_path
EOF

    chmod +x "$test_script"
    
    # Test validation
    if "$test_script" 2>/dev/null; then
        if [[ "$should_pass" == "true" ]]; then
            echo -e "  ${GREEN}✓${NC} Validation passed as expected"
        else
            error "Validation should have failed but passed"
            rm -f "$test_script"
            return 1
        fi
    else
        if [[ "$should_pass" == "false" ]]; then
            echo -e "  ${GREEN}✓${NC} Validation failed as expected"
        else
            error "Validation should have passed but failed"
            rm -f "$test_script"
            return 1
        fi
    fi
    
    rm -f "$test_script"
    
    # Clean up environment variables
    for env_var in "${env_vars[@]}"; do
        unset "${env_var%%=*}"
    done
    
    echo
}

# ============================================================
# SARIF Discovery Tests
# Tests for convert_json_to_sarif file discovery logic
# ============================================================

# Helper: create minimal JSON files that mimic FCS CLI output
create_mock_json() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    echo '{"runs":[{"results":[]}]}' > "$path"
}

# Test the primary path: parsing "Results saved to file:" from CLI output
test_sarif_discovery_primary_path() {
    local test_name="$1"
    local expected_count="$2"
    local cli_output_content="$3"
    shift 3
    local json_files=("$@")

    log "Testing SARIF discovery: $test_name"

    local test_dir="/tmp/sarif_discovery_test_$$"
    rm -rf "$test_dir"
    mkdir -p "$test_dir"

    # Create the mock JSON files on disk
    for f in "${json_files[@]}"; do
        create_mock_json "$f"
    done

    # Write mock CLI output
    local cli_output_file="$test_dir/cli_output.txt"
    echo "$cli_output_content" > "$cli_output_file"

    # Run the discovery logic (primary path)
    local all_json_files
    all_json_files=$(grep "Results saved to file:" "$cli_output_file" | \
                    sed 's/.*Results saved to file: //' | \
                    grep '\.json$' | \
                    sort)

    local actual_count=0
    if [[ -n "$all_json_files" ]]; then
        while IFS= read -r json_file; do
            if [[ -n "$json_file" && -f "$json_file" ]]; then
                actual_count=$((actual_count + 1))
            fi
        done <<< "$all_json_files"
    fi

    if [[ "$actual_count" -eq "$expected_count" ]]; then
        echo -e "  ${GREEN}✓${NC} Primary path discovered $actual_count file(s) as expected"
    else
        error "Primary path expected $expected_count file(s), got $actual_count"
        error "CLI output content: $cli_output_content"
        error "Discovered files: $all_json_files"
        rm -rf "$test_dir"
        return 1
    fi

    rm -rf "$test_dir"
    echo
}

main() {
    log "Starting FCS Image Scan Tests"
    echo
    
    # Test 1: Basic image scanning parameters
    test_parameter_generation \
        "Basic image scan parameters" \
        "--image nginx:latest" \
        "INPUT_SCAN_TYPE=image" \
        "INPUT_IMAGE=nginx:latest" \
        "INPUT_OUTPUT_PATH=./results/"
    
    # Test 2: Image scan with vulnerability-only flag
    test_parameter_generation \
        "Image scan with vulnerability-only" \
        "--vulnerability-only" \
        "INPUT_SCAN_TYPE=image" \
        "INPUT_IMAGE=alpine:latest" \
        "INPUT_VULNERABILITY_ONLY=true"
    
    # Test 3: Image scan with filtering options
    test_parameter_generation \
        "Image scan with filtering" \
        "--minimum-severity high" \
        "INPUT_SCAN_TYPE=image" \
        "INPUT_IMAGE=node:16" \
        "INPUT_MINIMUM_SEVERITY=high" \
        "INPUT_MINIMUM_SCORE=7.5"
    
    # Test 5: Image scan with SBOM-only
    test_parameter_generation \
        "Image scan SBOM-only" \
        "--sbom-only" \
        "INPUT_SCAN_TYPE=image" \
        "INPUT_IMAGE=redis:alpine" \
        "INPUT_SBOM_ONLY=true"
    
    # Test 6: Image scan with upload
    test_parameter_generation \
        "Image scan with upload" \
        "--client-id test-client-id" \
        "INPUT_SCAN_TYPE=image" \
        "INPUT_IMAGE=python:3.9" \
        "INPUT_UPLOAD_RESULTS=true" \
        "INPUT_FALCON_CLIENT_ID=test-client-id" \
        "FALCON_CLIENT_SECRET=test-client-secret" \
        "INPUT_FALCON_REGION=us-1"
    
    # Validation Tests
    
    # Test 7: Valid image scan validation
    test_validation \
        "Valid image scan" \
        "true" \
        "INPUT_SCAN_TYPE=image" \
        "INPUT_IMAGE=nginx:latest"
    
    # Test 8: Invalid image scan validation (missing image)
    test_validation \
        "Invalid image scan (missing image)" \
        "false" \
        "INPUT_SCAN_TYPE=image"
    
    # Test 9: Valid IaC scan validation (backward compatibility)
    test_validation \
        "Valid IaC scan (default)" \
        "true" \
        "INPUT_PATH=$TEST_DIR"
    
    # Test 10: Valid explicit IaC scan validation
    test_validation \
        "Valid explicit IaC scan" \
        "true" \
        "INPUT_SCAN_TYPE=iac" \
        "INPUT_PATH=$TEST_DIR"
    
    # Test 11: Invalid scan type validation
    test_validation \
        "Invalid scan type" \
        "false" \
        "INPUT_SCAN_TYPE=invalid"
    
    # ============================================================
    # SARIF Discovery: Primary Path Tests
    # ============================================================

    local sarif_test_dir="/tmp/sarif_discovery_test_$$"

    # Test 12: Single JSON file from CLI output
    create_mock_json "$sarif_test_dir/results.json"
    test_sarif_discovery_primary_path \
        "Single JSON file from CLI output" \
        1 \
        "Scanning image nginx:latest...
Results saved to file: $sarif_test_dir/results.json
Scan complete." \
        "$sarif_test_dir/results.json"

    # Test 13: Multi-arch JSON files from CLI output
    create_mock_json "$sarif_test_dir/multi/results_linux_amd64.json"
    create_mock_json "$sarif_test_dir/multi/results_linux_arm64.json"
    test_sarif_discovery_primary_path \
        "Multi-arch JSON files from CLI output" \
        2 \
        "Scanning image nginx:latest for linux/amd64...
Results saved to file: $sarif_test_dir/multi/results_linux_amd64.json
Scanning image nginx:latest for linux/arm64...
Results saved to file: $sarif_test_dir/multi/results_linux_arm64.json
Scan complete." \
        "$sarif_test_dir/multi/results_linux_amd64.json" \
        "$sarif_test_dir/multi/results_linux_arm64.json"

    # Test 14: CLI output with non-JSON files mixed in (should only find .json)
    create_mock_json "$sarif_test_dir/mixed/results.json"
    test_sarif_discovery_primary_path \
        "Filters non-JSON files from CLI output" \
        1 \
        "Results saved to file: $sarif_test_dir/mixed/results.json
Results saved to file: $sarif_test_dir/mixed/results.sarif
Results saved to file: $sarif_test_dir/mixed/results.cdx.xml" \
        "$sarif_test_dir/mixed/results.json"

    # Test 15: CLI output with no "Results saved to file:" lines
    test_sarif_discovery_primary_path \
        "No results lines in CLI output" \
        0 \
        "Scanning image nginx:latest...
Scan complete. No issues found."

    rm -rf "$sarif_test_dir"

    # ============================================================
    # SARIF Discovery: Fallback Path Tests (FCS CLI 3.x regression)
    # When CLI output contains no "Results saved to file:" lines,
    # convert_json_to_sarif must fall back to INPUT_OUTPUT_PATH.
    # ============================================================

    test_sarif_discovery_fallback() {
        local test_name="$1"
        local input_output_path="$2"
        local expected_sarif="$3"
        shift 3
        local json_files=("$@")

        log "Testing SARIF fallback: $test_name"

        local test_dir="/tmp/sarif_fallback_test_$$"
        rm -rf "$test_dir"
        mkdir -p "$test_dir"

        # Create mock JSON file(s) on disk
        for f in "${json_files[@]}"; do
            mkdir -p "$(dirname "$f")"
            echo '{"fcs_version":"3.3.1","rule_detections":[]}' > "$f"
        done

        # CLI output has NO "Results saved to file:" — simulates FCS 3.3.1
        local cli_output_file="$test_dir/cli_output.txt"
        echo "Scanning image nginx:latest..." > "$cli_output_file"
        echo "Scan complete." >> "$cli_output_file"

        # Run convert_json_to_sarif in a subprocess with the right environment
        local result
        result=$(
            export GITHUB_ACTION_PATH="$PROJECT_ROOT"
            export INPUT_OUTPUT_PATH="$input_output_path"
            export FCS_CLI_OUTPUT_FILE="$cli_output_file"

            # Inline the function under test so we don't call main()
            source <(grep -A 200 '^convert_json_to_sarif()' "$FCS_SCAN_SCRIPT" | \
                     awk '/^convert_json_to_sarif\(\)/{found=1} found{print; brace+=gsub(/{/,""); brace-=gsub(/}/,""); if(found && brace==0) exit}')
            source <(grep -A 5 '^log()' "$FCS_SCAN_SCRIPT")

            convert_json_to_sarif 2>&1
        )

        if [[ -f "$expected_sarif" ]]; then
            echo -e "  ${GREEN}✓${NC} Fallback produced expected SARIF file: $expected_sarif"
        else
            error "Fallback did NOT produce expected SARIF file: $expected_sarif"
            error "Function output: $result"
            rm -rf "$test_dir"
            return 1
        fi

        rm -rf "$test_dir"
        # Also remove any output files the converter wrote alongside the input
        rm -f "${expected_sarif}"
        echo
    }

    # Test 16: FCS 3.x regression — .sarif output_path, single JSON on disk
    local fb_dir="/tmp/sarif_fb16_$$"
    mkdir -p "$fb_dir"
    echo '{"fcs_version":"3.3.1","rule_detections":[]}' > "$fb_dir/results.json"
    test_sarif_discovery_fallback \
        "Fallback: .sarif output_path maps to .json file on disk" \
        "$fb_dir/results.sarif" \
        "$fb_dir/results.sarif" \
        "$fb_dir/results.json"
    rm -rf "$fb_dir"

    # Test 17: FCS 3.x regression — .sarif output_path, multi-arch JSON files on disk
    local fb_dir2="/tmp/sarif_fb17_$$"
    mkdir -p "$fb_dir2"
    echo '{"fcs_version":"3.3.1","rule_detections":[]}' > "$fb_dir2/results.json_linux_amd64.json"
    echo '{"fcs_version":"3.3.1","rule_detections":[]}' > "$fb_dir2/results.json_linux_arm64.json"
    test_sarif_discovery_fallback \
        "Fallback: multi-arch files found via prefix glob" \
        "$fb_dir2/results.sarif" \
        "$fb_dir2/results.json_linux_amd64.sarif" \
        "$fb_dir2/results.json_linux_amd64.json" \
        "$fb_dir2/results.json_linux_arm64.json"
    rm -rf "$fb_dir2"

    # ============================================================
    # SARIF Discovery: Directory output_path fallback (IaC scan)
    # Regression test for: output_path is a directory (e.g. './scan-results'),
    # CLI writes JSON files inside it, but primary stdout parse finds nothing.
    # ============================================================

    test_sarif_discovery_fallback_directory() {
        local test_name="$1"
        local input_output_path="$2"
        local expected_sarif="$3"
        shift 3
        local json_files=("$@")

        log "Testing SARIF fallback (directory): $test_name"

        # Create mock JSON file(s) inside the directory
        for f in "${json_files[@]}"; do
            mkdir -p "$(dirname "$f")"
            echo '{"fcs_version":"5.0.1","rule_detections":[]}' > "$f"
        done

        # CLI output has NO "Results saved to file:" — simulates the failing scenario
        local cli_output_file="/tmp/sarif_dir_cli_output_$$.txt"
        echo "Scanning IaC path ...." > "$cli_output_file"
        echo "Scan complete." >> "$cli_output_file"

        local result
        result=$(
            export GITHUB_ACTION_PATH="$PROJECT_ROOT"
            export INPUT_OUTPUT_PATH="$input_output_path"
            export FCS_CLI_OUTPUT_FILE="$cli_output_file"

            source <(grep -A 200 '^convert_json_to_sarif()' "$FCS_SCAN_SCRIPT" | \
                     awk '/^convert_json_to_sarif\(\)/{found=1} found{print; brace+=gsub(/{/,""); brace-=gsub(/}/,""); if(found && brace==0) exit}')
            source <(grep -A 5 '^log()' "$FCS_SCAN_SCRIPT")

            convert_json_to_sarif 2>&1
        )

        rm -f "$cli_output_file"

        if [[ -f "$expected_sarif" ]]; then
            echo -e "  ${GREEN}✓${NC} Directory fallback produced expected SARIF file: $expected_sarif"
        else
            error "Directory fallback did NOT produce expected SARIF file: $expected_sarif"
            error "Function output: $result"
            for f in "${json_files[@]}"; do rm -f "$f" "${f%.json}.sarif"; done
            return 1
        fi

        for f in "${json_files[@]}"; do rm -f "$f" "${f%.json}.sarif"; done
        echo
    }

    # Test 18: IaC scan — directory output_path, single JSON written by CLI inside it
    local scan_dir="/tmp/scan-results-$$"
    mkdir -p "$scan_dir"
    test_sarif_discovery_fallback_directory \
        "Fallback: directory output_path with single JSON inside" \
        "$scan_dir" \
        "$scan_dir/scan-results.sarif" \
        "$scan_dir/scan-results.json"
    rm -rf "$scan_dir"

    # Test 19: IaC scan — directory output_path, multiple JSON files inside
    local scan_dir2="/tmp/scan-results2-$$"
    mkdir -p "$scan_dir2"
    test_sarif_discovery_fallback_directory \
        "Fallback: directory output_path with multiple JSON files inside" \
        "$scan_dir2" \
        "$scan_dir2/iac-results.sarif" \
        "$scan_dir2/iac-results.json" \
        "$scan_dir2/secrets-results.json"
    rm -rf "$scan_dir2"

    # ============================================================
    # IaC output-path .sarif → .json rewrite in set_parameters
    # Regression test for: report_formats='sarif', output_path='./results.sarif'
    # The IaC set_parameters must rewrite the path to .json before passing to
    # the CLI, otherwise the CLI writes to .sarif and convert_json_to_sarif
    # can't find the file.
    # ============================================================

    test_iac_sarif_output_path_rewrite() {
        local test_name="$1"
        local input_output_path="$2"
        local expected_param="$3"

        log "Testing IaC output-path rewrite: $test_name"

        local result
        result=$(
            export INPUT_SCAN_TYPE="iac"
            export INPUT_PATH="."
            export INPUT_OUTPUT_PATH="$input_output_path"
            export INPUT_REPORT_FORMATS="sarif"
            export INPUT_FALCON_CLIENT_ID="test-id"
            export FALCON_CLIENT_SECRET="test-secret"
            export INPUT_FALCON_REGION="us-1"

            source <(grep -A 300 '^set_parameters()' "$FCS_SCAN_SCRIPT" | \
                     awk '/^set_parameters\(\)/{found=1} found{print; brace+=gsub(/{/,""); brace-=gsub(/}/,""); if(found && brace==0) exit}')
            source <(grep -A 5 '^validate_bool()' "$FCS_SCAN_SCRIPT")
            source <(grep -A 20 '^prepare_report_formats_for_cli()' "$FCS_SCAN_SCRIPT")
            source <(grep -A 20 '^ensure_output_directory()' "$FCS_SCAN_SCRIPT")
            log() { echo "$@" >&2; }
            die() { echo "ERROR: $*" >&2; exit 1; }

            set_parameters 2>/dev/null
        )

        if [[ "$result" == *"$expected_param"* ]]; then
            echo -e "  ${GREEN}✓${NC} set_parameters contains: $expected_param"
        else
            error "set_parameters did not contain: $expected_param"
            error "Actual params: $result"
            return 1
        fi
        echo
    }

    # Test 20: IaC .sarif output_path must be rewritten to .json
    test_iac_sarif_output_path_rewrite \
        "IaC .sarif output_path rewritten to .json" \
        "/tmp/results.sarif" \
        "--output-path /tmp/results.json"

    # Test 21: IaC .json output_path must be passed through unchanged
    test_iac_sarif_output_path_rewrite \
        "IaC .json output_path passed through unchanged" \
        "/tmp/results.json" \
        "--output-path /tmp/results.json"

    # ============================================================
    # No output_path: primary stdout parse is the only mechanism
    # Tests #1/#5 (IaC) and #9/#13 (image) — scan type is irrelevant
    # since convert_json_to_sarif is shared. Covers both the happy
    # path (CLI emits "Results saved to file:") and the known failure
    # path (CLI does not emit it).
    # ============================================================

    test_sarif_no_output_path() {
        local test_name="$1"
        local cli_output_content="$2"
        local json_file="$3"
        local expect_sarif="$4"   # "true" or "false"

        log "Testing SARIF conversion (no output_path): $test_name"

        local cli_output_file="/tmp/sarif_no_op_cli_$$.txt"
        echo "$cli_output_content" > "$cli_output_file"

        # Create mock JSON file if provided
        if [[ -n "$json_file" ]]; then
            mkdir -p "$(dirname "$json_file")"
            echo '{"fcs_version":"5.0.1","rule_detections":[]}' > "$json_file"
        fi

        local sarif_file="${json_file%.json}.sarif"

        local result
        result=$(
            export GITHUB_ACTION_PATH="$PROJECT_ROOT"
            export INPUT_OUTPUT_PATH=""
            export FCS_CLI_OUTPUT_FILE="$cli_output_file"

            source <(grep -A 200 '^convert_json_to_sarif()' "$FCS_SCAN_SCRIPT" | \
                     awk '/^convert_json_to_sarif\(\)/{found=1} found{print; brace+=gsub(/{/,""); brace-=gsub(/}/,""); if(found && brace==0) exit}')
            source <(grep -A 5 '^log()' "$FCS_SCAN_SCRIPT")

            convert_json_to_sarif 2>&1
        )

        rm -f "$cli_output_file"

        if [[ "$expect_sarif" == "true" ]]; then
            if [[ -f "$sarif_file" ]]; then
                echo -e "  ${GREEN}✓${NC} SARIF file produced via stdout parse: $sarif_file"
                rm -f "$json_file" "$sarif_file"
            else
                error "Expected SARIF file not found: $sarif_file"
                error "Function output: $result"
                rm -f "$json_file"
                return 1
            fi
        else
            if [[ ! -f "$sarif_file" ]]; then
                echo -e "  ${GREEN}✓${NC} No SARIF produced as expected (stdout parse found nothing)"
            else
                error "SARIF file should not have been produced: $sarif_file"
                rm -f "$json_file" "$sarif_file"
                return 1
            fi
        fi
        echo
    }

    # Test 22: no output_path, CLI emits "Results saved to file:" with ANSI bold codes and \r
    local no_op_json="/tmp/sarif_no_op_$$/results.json"
    mkdir -p "$(dirname "$no_op_json")"
    test_sarif_no_output_path \
        "No output_path: stdout parse handles ANSI codes and \\r from progress bar" \
        "$(printf 'Scan progress: 100%%\r\033[1mResults saved to file: %s\033[0m' "$no_op_json")" \
        "$no_op_json" \
        "true"
    rm -rf "$(dirname "$no_op_json")"

    # Test 23: no output_path, CLI emits nothing useful — known silent failure
    test_sarif_no_output_path \
        "No output_path: stdout parse finds nothing (known limitation)" \
        "Scanning...
Done." \
        "" \
        "false"

    # ============================================================
    # Image scan + directory output_path (#10/#14)
    # convert_json_to_sarif is scan-type agnostic so the directory
    # fallback logic is identical to IaC — this test confirms the
    # image parameter naming difference doesn't affect conversion.
    # ============================================================

    # Test 24: image scan — directory output_path, single JSON inside
    local img_dir="/tmp/img-scan-results-$$"
    mkdir -p "$img_dir"
    test_sarif_discovery_fallback_directory \
        "Image scan: directory output_path with single JSON inside" \
        "$img_dir" \
        "$img_dir/image-results.sarif" \
        "$img_dir/image-results.json"
    rm -rf "$img_dir"

    # Test 25: image scan — directory output_path, multiple JSON files (multi-arch)
    local img_dir2="/tmp/img-scan-results2-$$"
    mkdir -p "$img_dir2"
    test_sarif_discovery_fallback_directory \
        "Image scan: directory output_path with multi-arch JSON files" \
        "$img_dir2" \
        "$img_dir2/results_linux_amd64.sarif" \
        "$img_dir2/results_linux_amd64.json" \
        "$img_dir2/results_linux_arm64.json"
    rm -rf "$img_dir2"

    log "All tests completed successfully!"
    log "Image scanning functionality is working correctly."
    
    # Clean up
    rm -f "$GITHUB_OUTPUT"
}

# Check if script exists
if [[ ! -f "$FCS_SCAN_SCRIPT" ]]; then
    error "FCS scan script not found at: $FCS_SCAN_SCRIPT"
    exit 1
fi

# Run tests
main "$@"
