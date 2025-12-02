# CrowdStrike FCS Action Tests

This directory contains tests for the CrowdStrike FCS GitHub Action, including both IaC (Infrastructure as Code) and image scanning capabilities.

## Test Files

- `test-files/` - Directory containing different IaC sample files
- `config.json` - Configuration file for IaC scanning tests
- `image-scan-test.yml` - GitHub Actions workflow for testing image scanning functionality
- `test-image-scan.sh` - Shell script for local testing of image scanning parameters
- `test-fcs-scan-image-direct.sh` - Direct test script for the fcs CLI binary using nginx:latest

## Running Tests

### Local Testing

#### GitHub Action Parameter Testing

To test the image scanning functionality locally:

```bash
# Make the test script executable (if not already done)
chmod +x tests/test-image-scan.sh

# Run the test script
./tests/test-image-scan.sh
```

This script will test:

- Parameter generation for different image scanning scenarios
- Validation logic for both IaC and image scanning
- Backward compatibility with existing IaC functionality

#### Direct FCS CLI Testing

To test the FCS CLI binary directly with nginx:latest:

```bash
# Make the direct test script executable (if not already done)
chmod +x tests/test-fcs-scan-image-direct.sh

# Run the direct test script
./tests/test-fcs-scan-image-direct.sh
```

This comprehensive test script will:

- Test 20 different scanning scenarios using nginx:latest
- Cover all available options from `./fcs scan image --help`
- Generate test outputs for verification
- Test various combinations of flags and parameters

Test scenarios include:

- Basic image scanning
- Vulnerability-only and SBOM-only modes
- Different output formats (JSON, SARIF, CycloneDX)
- Filtering by severity, score, and ExPRT ratings
- Advanced options like full descriptions and detection details
- Platform specification and custom temp directories
- Combined filtering scenarios

Test outputs are saved to `test-outputs/` directory for inspection.

### GitHub Actions Testing

The `image-scan-test.yml` workflow can be triggered:

- Manually via workflow dispatch
- On push to main branch
- On pull requests to main branch

The workflow includes comprehensive tests for:

- Basic image scanning
- Vulnerability-only scanning
- Advanced filtering options
- SBOM generation
- Upload to Falcon Console
- Backward compatibility with IaC scanning

## Image Scanning Usage Examples

### Basic Image Scanning

```yaml
- name: Scan container image
  uses: CrowdStrike/fcs-action@v1
  with:
    falcon_client_id: ${{ secrets.FALCON_CLIENT_ID }}
    falcon_region: us-1
    scan_type: image
    image: nginx:latest
    output_path: ./scan-results/
    report_formats: json
```

### Vulnerability-Only Scanning

```yaml
- name: Scan for vulnerabilities only
  uses: CrowdStrike/fcs-action@v1
  with:
    falcon_client_id: ${{ secrets.FALCON_CLIENT_ID }}
    falcon_region: us-1
    scan_type: image
    image: alpine:latest
    vulnerability_only: true
    minimum_severity: high
    report_formats: json,sarif
```

### Advanced Filtering

```yaml
- name: Scan with advanced filtering
  uses: CrowdStrike/fcs-action@v1
  with:
    falcon_client_id: ${{ secrets.FALCON_CLIENT_ID }}
    falcon_region: us-1
    scan_type: image
    image: node:16-alpine
    minimum_score: 7.5
    minimum_severity: medium
    vuln_fixable_only: true
    show_full_description: true
    report_sort_by: severity/desc
```

### SBOM Generation

```yaml
- name: Generate SBOM
  uses: CrowdStrike/fcs-action@v1
  with:
    falcon_client_id: ${{ secrets.FALCON_CLIENT_ID }}
    falcon_region: us-1
    scan_type: image
    image: python:3.9-slim
    sbom_only: true
    report_formats: sbom-cylconedx
```

### Upload Results to Falcon Console

```yaml
- name: Scan and upload to Falcon
  uses: CrowdStrike/fcs-action@v1
  with:
    falcon_client_id: ${{ secrets.FALCON_CLIENT_ID }}
    falcon_region: us-1
    scan_type: image
    image: myapp:latest
    upload_results: true
```

## IaC Scanning (Backward Compatible)

The action continues to support IaC scanning with the same parameters as before:

```yaml
# Default behavior (IaC scanning)
- name: Scan IaC files
  uses: CrowdStrike/fcs-action@v1
  with:
    falcon_client_id: ${{ secrets.FALCON_CLIENT_ID }}
    falcon_region: us-1
    path: ./terraform
    report_formats: json,sarif

# Explicit IaC scanning
- name: Explicit IaC scan
  uses: CrowdStrike/fcs-action@v1
  with:
    falcon_client_id: ${{ secrets.FALCON_CLIENT_ID }}
    falcon_region: us-1
    scan_type: iac
    path: ./infrastructure
    severities: high,critical
```

## Available Parameters

### Common Parameters

- `falcon_client_id` - CrowdStrike API Client ID (required)
- `falcon_region` - CrowdStrike API region (required)
- `scan_type` - Type of scan: `iac` or `image` (default: `iac`)
- `output_path` - Path to save scan results
- `report_formats` - Output formats (json, sarif, sbom-cylconedx)
- `upload_results` - Upload results to Falcon Console

### Image Scanning Parameters

- `image` - Container image to scan (required for image scanning)
- `socket` - Custom container engine socket path
- `platform` - Target platform (e.g., linux/amd64, linux/arm64)
- `vulnerability_only` - Scan for vulnerabilities only
- `sbom_only` - Generate SBOM only
- `minimum_score` - Minimum CVSS score threshold (0.0-10.0)
- `minimum_severity` - Minimum severity (low, medium, high, critical)
- `minimum_exprt` - Minimum ExPRT rating (low, medium, high, critical)
- `exclude_vulnerabilities` - Comma-separated list of CVE IDs to exclude
- `vuln_fixable_only` - Exclude vulnerabilities without fixes
- `report_sort_by` - Sort results by vulnerability, severity, score, or ExPRT
- `show_full_description` - Show full vulnerability descriptions
- `show_full_detection_details` - Show full detection details
- `minimum_detection_severity` - Minimum detection severity
- `no_color` - Disable colored output
- `temp_dir` - Custom temporary directory

### IaC Scanning Parameters

- `path` - Path to scan (required for IaC scanning)
- `config` - Configuration file path
- `categories` - Include specific categories
- `exclude_categories` - Exclude specific categories
- `exclude_paths` - Exclude specific paths
- `exclude_platforms` - Exclude specific platforms
- `exclude_severities` - Exclude specific severities
- `platforms` - Include specific platforms
- `severities` - Include specific severities
- `policy_rule` - Policy rule to use
- `project_owners` - Project owners to notify
- `disable_secrets_scan` - Disable secrets scanning
- `fail_on` - Conditions that should cause failure
- `timeout` - Scan timeout

## Test Requirements

### Required Secrets

For running the GitHub Actions tests, you'll need these secrets configured:

- `FALCON_CLIENT_ID` - CrowdStrike Falcon API client ID
- `FALCON_CLIENT_SECRET` - CrowdStrike Falcon API client secret

### Test Images

The tests use publicly available images:

- `nginx:latest`
- `alpine:latest`
- `ubuntu:20.04`
- `node:16-alpine`
- `python:3.9-slim`
- `redis:alpine`

These images are chosen to provide a variety of vulnerability profiles for testing different scanning scenarios.

## Troubleshooting

### Common Issues

1. **Missing image parameter**: Ensure `image` is specified when `scan_type` is `image`
2. **Platform issues**: Specify `platform` for multi-arch images if needed
3. **Output directory**: Ensure `output_path` directory exists or can be created
4. **Report formats**: Use valid format names (json, sarif, sbom-cylconedx)

### Debug Mode

To enable verbose logging, set the scan parameters to show full details:

```yaml
show_full_description: true
show_full_detection_details: true
```

This will provide more detailed information in the scan results for troubleshooting.
