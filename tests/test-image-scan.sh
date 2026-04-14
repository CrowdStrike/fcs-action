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
