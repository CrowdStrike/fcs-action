#!/bin/bash
#
# Download and extract FCS CLI using the v2 API endpoint.
#

set -euo pipefail

# Configuration
TEMP_DIR=$(mktemp -d)
readonly TEMP_DIR
trap 'rm -rf "$TEMP_DIR"' EXIT

# Function to get API base URL for region
get_region_base_url() {
    local region="$1"
    case "$region" in
        "us-1") echo "api.crowdstrike.com" ;;
        "us-2") echo "api.us-2.crowdstrike.com" ;;
        "eu-1") echo "api.eu-1.crowdstrike.com" ;;
        "us-gov-1") echo "api.laggar.gcw.crowdstrike.com" ;;
        "us-gov-2") echo "api.us-gov-2.crowdstrike.mil" ;;
        *) echo "api.crowdstrike.com" ;;
    esac
}

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" >&2
}

# Function to get OAuth2 token
get_oauth_token() {
    local client_id="$1"
    local client_secret="$2" 
    local base_url="$3"
    
    local token_response
    token_response=$(curl -s -X POST "https://${base_url}/oauth2/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=${client_id}&client_secret=${client_secret}&grant_type=client_credentials")
    
    if ! echo "$token_response" | jq -e '.access_token' > /dev/null 2>&1; then
        log_error "Failed to get OAuth token"
        log_error "Response: $token_response"
        return 1
    fi
    
    echo "$token_response" | jq -r '.access_token'
}

# Function to detect OS and architecture separately
detect_platform() {
    local system
    local machine
    system=$(uname -s | tr '[:upper:]' '[:lower:]')
    machine=$(uname -m | tr '[:upper:]' '[:lower:]')
    
    local os arch
    
    case "$system" in
        linux)
            os="linux"
            ;;
        darwin)
            os="darwin"
            ;;
        mingw*|cygwin*|msys*)
            os="windows"
            ;;
        *)
            log_warn "Unknown system: $system, defaulting to linux"
            os="linux"
            ;;
    esac
    
    case "$machine" in
        aarch64|arm64) arch="arm64" ;;
        x86_64|amd64) arch="amd64" ;;
        *)
            log_warn "Unknown architecture: $machine, defaulting to amd64"
            arch="amd64"
            ;;
    esac
    
    echo "${os} ${arch}"
}

# Function to call the v2 files-download API
get_fcs_download_info() {
    local token="$1"
    local base_url="$2"
    local platform="$3"
    local version="$4"
    
    # Parse OS and architecture from platform
    local os
    local arch
    os=$(echo "$platform" | cut -d' ' -f1)
    arch=$(echo "$platform" | cut -d' ' -f2)
    
    local api_url="https://${base_url}/csdownloads/combined/files-download/v2"
    local filter
    
    # Build filter parameter
    if [[ -n "$version" ]]; then
        filter="category:'fcs'+os:'${os}'+arch:'${arch}'+file_version:'${version}'"
    else
        filter="category:'fcs'+os:'${os}'+arch:'${arch}'"
    fi
    
    # Simple URL encoding for the filter
    local encoded_filter
    encoded_filter=$(echo "$filter" | sed "s/+/%2B/g; s/:/%3A/g; s/'/%27/g")
    
    local response
    response=$(curl -s -X GET "$api_url?filter=${encoded_filter}&limit=100&sort=file_version%7Cdesc" \
        -H "accept: application/json" \
        -H "Authorization: Bearer $token")
    
    # Check if response contains errors
    if echo "$response" | jq -e '.errors' > /dev/null 2>&1; then
        log_error "API returned errors:"
        echo "$response" | jq -r '.errors[] | "  - \(.message)"'
        return 1
    fi
    
    # Check if we have resources
    if ! echo "$response" | jq -e '.resources[0]' > /dev/null 2>&1; then
        log_error "No resources found in API response"
        log_error "Response: $response"
        return 1
    fi
    
    echo "$response"
}

# Function to extract download info from API response (gets latest version)
extract_download_details() {
    local response="$1"
    local detail_type="$2"  # download_url, file_name, file_hash, version
    
    # API returns results sorted by file_version:desc, so first element is the latest
    case "$detail_type" in
        "download_url")
            echo "$response" | jq -r ".resources[0].download_info.download_url // empty"
            ;;
        "file_name")
            echo "$response" | jq -r ".resources[0].file_name // empty"
            ;;
        "file_hash")
            echo "$response" | jq -r ".resources[0].download_info.file_hash // .resources[0].file_hash // empty"
            ;;
        "version")
            echo "$response" | jq -r ".resources[0].file_version // empty"
            ;;
        *)
            echo "$response" | jq -r ".resources[0].$detail_type // empty"
            ;;
    esac
}

# Function to download file with hash validation
download_and_validate_file() {
    local download_url="$1"
    local file_name="$2"
    local expected_hash="$3"
    local output_dir="$4"
    
    local output_path="$output_dir/$file_name"
    
    if ! curl -L -o "$output_path" "$download_url"; then
        log_error "Download failed"
        return 1
    fi

    local file_hash
    if command -v sha256sum > /dev/null; then
        file_hash=$(sha256sum "$output_path" | cut -d' ' -f1)
    elif command -v shasum > /dev/null; then
        file_hash=$(shasum -a 256 "$output_path" | cut -d' ' -f1)
    else
        log_error "No SHA256 utility available"
        return 1
    fi
    
    # Convert hashes to lowercase for comparison
    local file_hash_lower
    local expected_hash_lower
    file_hash_lower=$(echo "$file_hash" | tr '[:upper:]' '[:lower:]')
    expected_hash_lower=$(echo "$expected_hash" | tr '[:upper:]' '[:lower:]')
    
    if [[ "$file_hash_lower" == "$expected_hash_lower" ]]; then
        echo -e "${GREEN}[SUCCESS]${NC} File hash validated successfully" >&2
        echo "$output_path"
        return 0
    else
        log_error "Hash mismatch!"
        log_error "Expected: $expected_hash"
        log_error "Got:      $file_hash"
        return 1
    fi
}

# Function to extract and setup FCS binary
extract_and_setup_fcs() {
    local archive_path="$1"
    local bin_path="$2"
    
    # Create bin directory
    mkdir -p "$bin_path"
    
    local fcs_binary="fcs"
    if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == CYGWIN* || "$(uname -s)" == MSYS* ]]; then
        fcs_binary="fcs.exe"
    fi
    
    local fcs_path="$bin_path/$fcs_binary"
    
    # Extract based on file extension
    if [[ "$archive_path" == *.tar.gz ]]; then
        # Extract tar.gz
        
        if ! tar -xzf "$archive_path" -C "$TEMP_DIR"; then
            log_error "Failed to extract tar.gz file"
            log_error "DEBUG: tar command failed for: '$archive_path'"
            return 1
        fi
        
        # Find the fcs binary
        local extracted_fcs
        extracted_fcs=$(find "$TEMP_DIR" -name "fcs" -o -name "fcs.exe" | head -n1)
        
        if [[ -z "$extracted_fcs" ]]; then
            log_error "FCS binary not found in archive"
            return 1
        fi
        
        cp "$extracted_fcs" "$fcs_path"
        
    elif [[ "$archive_path" == *.zip ]]; then
        # Extract zip
        if ! unzip -q "$archive_path" -d "$TEMP_DIR"; then
            log_error "Failed to extract zip file"
            return 1
        fi
        
        # Find the fcs binary
        local extracted_fcs
        extracted_fcs=$(find "$TEMP_DIR" -name "fcs" -o -name "fcs.exe" | head -n1)
        
        if [[ -z "$extracted_fcs" ]]; then
            log_error "FCS binary not found in archive"
            return 1
        fi
        
        cp "$extracted_fcs" "$fcs_path"
    else
        log_error "Unsupported archive format: $archive_path"
        return 1
    fi
    
    # Make executable on Unix-like systems
    if [[ "$(uname -s)" != MINGW* && "$(uname -s)" != CYGWIN* && "$(uname -s)" != MSYS* ]]; then
        chmod +x "$fcs_path"
    fi
    
    # Create log directory that FCS expects
    local log_dir="$HOME/.crowdstrike/log"
    mkdir -p "$log_dir"
    
    log_success "FCS binary ready at: $fcs_path"
    echo "$fcs_path"
}

# Function to set GitHub Actions output
set_github_output() {
    local name="$1"
    local value="$2"
    
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        echo "$name=$value" >> "$GITHUB_OUTPUT"
    else
        # Fallback for older runners
        echo "::set-output name=$name::$value"
    fi
}

# Main function
main() {
    log_info "============================================================"
    log_info "CrowdStrike FCS download with v2 API endpoint"
    log_info "============================================================"
    
    # Get inputs from environment (GitHub Actions sets these)
    local bin_path="${INPUT_BIN_PATH:-${RUNNER_TEMP:-/tmp}}"
    local client_id="${INPUT_FALCON_CLIENT_ID:-}"
    local client_secret="${FALCON_CLIENT_SECRET:-}"
    local region="${INPUT_FALCON_REGION:-us-1}"
    local version="${INPUT_VERSION:-}"
    
    # Validate required inputs
    if [[ -z "$client_id" ]]; then
        log_error "INPUT_FALCON_CLIENT_ID environment variable is required"
        exit 1
    fi
    
    if [[ -z "$client_secret" ]]; then
        log_error "FALCON_CLIENT_SECRET environment variable is required"
        log_error "   This should be set by the workflow using:"
        log_error "   env:"
        log_error "     FALCON_CLIENT_SECRET: \${{ secrets.FALCON_CLIENT_SECRET }}"
        exit 1
    fi
    
    # Get API base URL
    local base_url
    base_url=$(get_region_base_url "$region")
    
    log_info "Configuration:"
    log_info "   Region: $region"
    log_info "   Base URL: $base_url"
    log_info "   Version: ${version:-latest}"
    log_info "   Bin Path: $bin_path"
    
    # Check required tools
    for tool in curl jq tar unzip; do
        if ! command -v "$tool" > /dev/null; then
            log_error "Required tool not found: $tool"
            exit 1
        fi
    done
    
    # Step 1: Get OAuth token
    local token
    if ! token=$(get_oauth_token "$client_id" "$client_secret" "$base_url"); then
        log_error "Failed to get OAuth token"
        exit 1
    fi
    
    # Step 2: Detect platform
    local platform
    platform=$(detect_platform)
    
    # Step 3: Get download info from v2 API
    local download_response
    if ! download_response=$(get_fcs_download_info "$token" "$base_url" "$platform" "$version"); then
        log_error "Failed to get FCS download information"
        exit 1
    fi
    
    # Step 4: Extract download details
    local download_url file_name file_hash file_version
    download_url=$(extract_download_details "$download_response" "download_url")
    file_name=$(extract_download_details "$download_response" "file_name")
    file_hash=$(extract_download_details "$download_response" "file_hash")
    file_version=$(extract_download_details "$download_response" "version")
    
    if [[ -z "$download_url" || -z "$file_name" || -z "$file_hash" ]]; then
        log_error "Missing required download details"
        log_error "Download URL: $download_url"
        log_error "File Name: $file_name"
        log_error "File Hash: $file_hash"
        exit 1
    fi

    log_info "Found FCS version: ${file_version:-unknown}"
    
    # Step 5: Download and validate file
    local downloaded_file
    if ! downloaded_file=$(download_and_validate_file "$download_url" "$file_name" "$file_hash" "$TEMP_DIR"); then
        log_error "Failed to download or validate FCS file"
        exit 1
    fi
    
    # Step 6: Extract and setup FCS binary
    local fcs_binary_path
    if ! fcs_binary_path=$(extract_and_setup_fcs "$downloaded_file" "$bin_path"); then
        log_error "Failed to extract and setup FCS binary"
        exit 1
    fi
    
    # Step 7: Set GitHub Actions outputs
    set_github_output "FCS_BIN" "$fcs_binary_path"
    
    # Add to GitHub Actions PATH
    if [[ -n "${GITHUB_PATH:-}" ]]; then
        echo "$bin_path" >> "$GITHUB_PATH"
    fi
    
    log_success ""
    log_success "FCS download completed successfully!"
    log_success "FCS binary: $fcs_binary_path"
    log_success ""
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
