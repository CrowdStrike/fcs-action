# FCS CLI GitHub Action

This GitHub Action allows you to run the CrowdStrike Falcon Cloud Security (FCS) CLI tool directly in your CI/CD pipeline. The action supports both Infrastructure as Code (IaC) scanning for misconfigurations and security vulnerabilities, as well as container image scanning for vulnerabilities and security issues.

## Features

- **IaC Scanning**: Run FCS IaC scans on local files, directories, or Git repositories
- **Image Scanning**: Scan container images for vulnerabilities, malware, and security issues
- **SBOM Generation**: Generate Software Bill of Materials (SBOM) in CycloneDX format
- Customize scan parameters such as categories, platforms, severities, and filtering options
- Generate scan reports in various formats (JSON, SARIF, SBOM)
- Upload scan results to the CrowdStrike Falcon Console
- Flexible configuration options for tailoring scans to your needs
- Support for vulnerability-only and SBOM-only scanning modes

## Prerequisites

### Create a CrowdStrike API Client

> [!NOTE]
> API clients are granted one or more API scopes. Scopes allow access to specific CrowdStrike APIs and describe the actions that an API client can perform. To create an API client, see [API Clients and Keys](https://falcon.crowdstrike.com/login/?unilogin=true&next=/api-clients-and-keys).

Ensure the following API scopes are assigned to the client:

- **Sensor Download**[read]
- **Infrastructure as Code**[read,write]

### Create a GitHub Secret

This action relies on the environment variable `FALCON_CLIENT_SECRET` to authenticate with the CrowdStrike API.

Create a GitHub secret in your repository to store the CrowdStrike API Client secret created from the step above. For more information, see [Creating secrets for a repository](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions#creating-secrets-for-a-repository).

### FCS Action Support for FCS CLI Versions

| **FCS CLI Version** | **FCS Action Version** |
| ------------------- | ---------------------- |
| **`>= 1.0.0`**      | **`>= 1.1.0`**         |
| **`< 1.0.0`**       | **`< 1.1.0`**          |

## Usage

To use this action in your workflow, add the following step:
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v1.1.0
  with:
    falcon_client_id: 'abcdefghijk123456789'
    falcon_region: 'us-1'
    path: './my-iac-directory'
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->

## Environment Variables

| Variable               | Description                                      | Required | Default | Example/Allowed Values                |
| ---------------------- | ------------------------------------------------ | -------- | ------- | ------------------------------------- |
| `FALCON_CLIENT_SECRET` | CrowdStrike API Client Secret for authentication | **Yes**  | -       | `${{ secrets.FALCON_CLIENT_SECRET }}` |

## Inputs

| Input                           | Description                                                                                                      | Required | Default                                      | Example/Allowed Values                                                                                                                                                                                                                                               |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------- | -------- | -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `falcon_client_id`              | CrowdStrike API Client ID for authentication                                                                     | **Yes**  | -                                            | `${{ vars.FALCON_CLIENT_ID }}`                                                                                                                                                                                                                                       |
| `falcon_region`                 | CrowdStrike API region                                                                                           | **Yes**  | `us-1`                                       | Allowed values: `us-1, us-2, eu-1, us-gov-1, us-gov-2`                                                                                                                                                                                                               |
| `version`                       | **FCS CLI tool** version to use (_not the GitHub Action version_)                                                | No       | -                                            | `1.0.0`                                                                                                                                                                                                                                                             |
| `scan_type`                     | Type of scan to perform                                                                                          | No       | `iac`                                        | Allowed values: `iac, image`                                                                                                                                                                                                                                         |
| **IaC Scanning Parameters**     |                                                                                                                  |          |                                              |                                                                                                                                                                                                                                                                      |
| `categories`                    | Include results for the specified categories, accepts a comma-separated list                                     | No       | -                                            | `Access Control,Best Practices`                                                                                                                                                                                                                                      |
| `config`                        | Path to the scan configuration file                                                                              | No       | -                                            | `./fcs-config.json`                                                                                                                                                                                                                                                  |
| `disable_secrets_scan`          | Disable scanning of secrets and passwords in target files                                                        | No       | `false`                                      | Allowed values: `true, false`                                                                                                                                                                                                                                        |
| `exclude_categories`            | Exclude results for the specified categories, accepts a comma-separated list                                     | No       | -                                            | Allowed values: `Access Control, Availability, Backup, Best Practices, Build Process, Encryption, Insecure Configurations, Insecure Defaults, Networking and Firewall, Observability, Resource Management, Secret Management, Supply-Chain, Structure and Semantics` |
| `exclude_paths`                 | Exclude paths from scan                                                                                          | No       | -                                            | `./sample-dir-to-omit/*,sample-file.tf`                                                                                                                                                                                                                              |
| `exclude_platforms`             | Exclude results for the specified platforms, accepts a comma-separated list                                      | No       | -                                            | `Ansible, AzureResourceManager, CloudFormation, Crossplane, DockerCompose, Dockerfile, GoogleDeploymentManager, Kubernetes, OpenAPI, Pulumi, ServerlessFW, Terraform`                                                                                                |
| `exclude_severities`            | Exclude results for the specified severities, accepts a comma-separated list                                     | No       | -                                            | Allowed values: `critical, high, medium, informational`                                                                                                                                                                                                                              |
| `fail_on`                       | Which kind of results should return a non-zero exit code, accepts a comma-separated list of `<severity>=<value>` | No       | `critical=1,high=1,medium=1,informational=1` |                                                                                                                                                                                                                                                                      |
| `path`                          | Path to local file, directory or git repo to scan                                                                | No       | -                                            | `./my-local-dir, git::<git repo>, sample-file.tf`                                                                                                                                                                                                                    |
| `platforms`                     | Include results for the specified platforms, accepts a comma-separated list                                      | No       | -                                            | `Ansible, AzureResourceManager, CloudFormation, Crossplane, DockerCompose, Dockerfile, GoogleDeploymentManager, Kubernetes, OpenAPI, Pulumi, ServerlessFW, Terraform`                                                                                                |
| `policy_rule`                   | IaC cloud scanning policy-rule                                                                                   | No       | `local`                                      | `local`, `default-iac-alert-rule`                                                                                                                                                                                                                                    |
| `project_owners`                | Comma-separated list of project owners to notify (max 5)                                                         | No       | -                                            | `john@example.com,jane@example.com`                                                                                                                                                                                                                                  |
| `severities`                    | Include results for the specified severities, accepts a comma-separated list                                     | No       | -                                            | Allowed values: `critical, high, medium, informational`                                                                                                                                                                                                                              |
| `timeout`                       | Timeout for the scan in seconds                                                                                  | No       | `500`                                        | `900`                                                                                                                                                                                                                                                                |
| **Image Scanning Parameters**   |                                                                                                                  |          |                                              |                                                                                                                                                                                                                                                                      |
| `image`                         | Container image to scan (required for image scanning)                                                            | **Yes*** | -                                            | `nginx:latest, quay.io/org/app:v1.0`                                                                                                                                                                                                                                 |
| `socket`                        | Custom socket path for container engine                                                                          | No       | -                                            | `unix:///var/run/docker.sock`                                                                                                                                                                                                                                        |
| `platform`                      | Target platform for multi-platform images                                                                       | No       | `linux/amd64`                                | `linux/amd64, linux/arm64, windows/amd64`                                                                                                                                                                                                                            |
| `vulnerability_only`            | Scan for vulnerabilities only                                                                                   | No       | `false`                                      | Allowed values: `true, false`                                                                                                                                                                                                                                        |
| `sbom_only`                     | Generate SBOM only                                                                                               | No       | `false`                                      | Allowed values: `true, false`                                                                                                                                                                                                                                        |
| `minimum_score`                 | Only show vulnerabilities with CVSS score at or above this threshold                                            | No       | -                                            | `0.0-10.0`                                                                                                                                                                                                                                                            |
| `minimum_severity`              | Only show vulnerabilities with this severity or higher                                                           | No       | -                                            | Allowed values: `low, medium, high, critical`                                                                                                                                                                                                                        |
| `minimum_exprt`                 | Only show vulnerabilities with this ExPRT rating or higher                                                       | No       | -                                            | Allowed values: `low, medium, high, critical`                                                                                                                                                                                                                        |
| `exclude_vulnerabilities`       | Comma-separated list of vulnerability IDs to exclude                                                            | No       | -                                            | `CVE-2023-1234,CVE-2023-5678`                                                                                                                                                                                                                                        |
| `vuln_fixable_only`             | Exclude vulnerabilities without a fix                                                                           | No       | `false`                                      | Allowed values: `true, false`                                                                                                                                                                                                                                        |
| `report_sort_by`                | Sort report by vulnerability, ExPRT rating, severity or score                                                    | No       | -                                            | `severity/asc, score/desc, vulnerability/asc`                                                                                                                                                                                                                        |
| `show_full_description`         | Show full vulnerability descriptions without truncation                                                           | No       | `false`                                      | Allowed values: `true, false`                                                                                                                                                                                                                                        |
| `show_full_detection_details`   | Show full detection details without truncation                                                                   | No       | `false`                                      | Allowed values: `true, false`                                                                                                                                                                                                                                        |
| `minimum_detection_severity`    | Only show detections with this severity or higher                                                                | No       | -                                            | Allowed values: `low, medium, high, critical`                                                                                                                                                                                                                        |
| `no_color`                      | Disable colored output for severity levels and ExPRT ratings                                                     | No       | `false`                                      | Allowed values: `true, false`                                                                                                                                                                                                                                        |
| `temp_dir`                      | Custom directory for temporary files                                                                             | No       | -                                            | `./temp`                                                                                                                                                                                                                                                              |
| **Common Parameters**           |                                                                                                                  |          |                                              |                                                                                                                                                                                                                                                                      |
| `output_path`                   | Path to save the scan results                                                                                    | No       | `./`                                         | `./scan-results`                                                                                                                                                                                                                                                     |
| `report_formats`                | Formats in which reports are to be written, accepts a comma-separated list                                       | No       | `json`                                       | IaC: `json, csv, junit, sarif`; Image: `json, sarif, sbom-cylconedx`                                                                                                                                                                                                 |
| `upload_results`                | Upload scan results to the CrowdStrike Falcon Console                                                            | No       | `false`                                      | `true`                                                                                                                                                                                                                                                               |

## Outputs

| Output      | Description                   |
| ----------- | ----------------------------- |
| `exit-code` | Exit code of the FCS CLI tool |

## Examples

### Basic scan of a local file
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v1.1.0
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'us-1'
    path: './sample-file.tf'
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->

### Specifying severity levels
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v1.1.0
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'us-2'
    path: './kubernetes'
    severities: 'critical,high,medium'
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->

### Using the policy rule parameter
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v1.1.0
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'us-2'
    path: './kubernetes'
    policy_rule: 'default-iac-alert-rule'
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->

### Upload SARIF report to GitHub Code scanning on non-zero exit code
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v1.1.0
  id: fcs
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'eu-1'
    path: './cloudformation'
    report_formats: 'sarif'
    output_path: './scan-results'
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}

- name: Upload SARIF report to GitHub Code scanning
    uses: github/codeql-action/upload-sarif@v3
    if: steps.fcs.outputs.exit-code != 0
    with:
      sarif_file: ./scan-results
```
<!-- x-release-please-end -->

### Scan with exclusions and severity filtering
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v1.1.0
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'us-2'
    path: './kubernetes'
    exclude_paths: './test/*,./deprecated/*'
    severities: 'high,medium'
    fail_on: 'high=10,medium=70'
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->

## Image Scanning Examples

### Basic container image scan
<!-- x-release-please-start-version -->
```yaml
- name: Scan Container Image
  uses: crowdstrike/fcs-action@v1.1.0
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'us-1'
    scan_type: image
    image: nginx:latest
    output_path: './image-scan-results/'
    report_formats: json
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->

### Vulnerability-only image scan with filtering
<!-- x-release-please-start-version -->
```yaml
- name: Scan Image for Vulnerabilities Only
  uses: crowdstrike/fcs-action@v1.1.0
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'us-2'
    scan_type: image
    image: alpine:latest
    vulnerability_only: true
    minimum_severity: high
    minimum_score: 7.0
    vuln_fixable_only: true
    report_formats: json,sarif
    output_path: './vuln-results/'
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->

### Generate SBOM for container image
<!-- x-release-please-start-version -->
```yaml
- name: Generate SBOM
  uses: crowdstrike/fcs-action@v1.1.0
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'eu-1'
    scan_type: image
    image: python:3.9-slim
    sbom_only: true
    report_formats: sbom-cylconedx
    output_path: './sbom-results/'
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->

### Advanced image scan with comprehensive filtering
<!-- x-release-please-start-version -->
```yaml
- name: Advanced Image Scan
  uses: crowdstrike/fcs-action@v1.1.0
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'us-1'
    scan_type: image
    image: node:16-alpine
    minimum_severity: medium
    minimum_exprt: medium
    exclude_vulnerabilities: 'CVE-2023-1234,CVE-2023-5678'
    show_full_description: true
    show_full_detection_details: true
    report_sort_by: severity/desc
    no_color: true
    platform: linux/amd64
    output_path: './detailed-scan-results/'
    report_formats: json
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->

### Upload image scan results to Falcon Console
<!-- x-release-please-start-version -->
```yaml
- name: Scan and Upload to Falcon
  uses: crowdstrike/fcs-action@v1.1.0
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'us-1'
    scan_type: image
    image: myapp:latest
    upload_results: true
    minimum_severity: low
    output_path: './upload-results/'
    report_formats: json
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->

### Multi-platform image scan
<!-- x-release-please-start-version -->
```yaml
- name: Scan Multi-Platform Image
  uses: crowdstrike/fcs-action@v1.1.0
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'us-2'
    scan_type: image
    image: nginx:latest
    platform: linux/arm64
    minimum_detection_severity: medium
    temp_dir: './custom-temp'
    output_path: './multi-platform-results/'
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->

---

You can also use configuration files to customize the scan parameters. For more information, see the [FCS CLI documentation](https://falcon.crowdstrike.com/login/?unilogin=true&next=/documentation/page/e08ea90a/infrastructure-as-code-security#u253ccc1)

### Run scan with configuration file
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v1.1.0
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'us-1'
    config: './fcs-config.json'
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->
> Example configuration file: `./fcs-config.json`

```json
{
    "path": "./scan-dir",
    "fail-on": [
        "critical=1",
        "high=1",
        "medium=1",
        "informational=1"
    ],
    "output-path": "./results",
    "report-formats": [
        "json",
        "sarif"
    ],
    "timeout": 300
}
```

## SARIF Output Transformation

When SARIF format reports are generated, the action automatically applies transformations to ensure compatibility with GitHub's SARIF 2.1.0 parsing requirements:

### Transformations Applied

1. **Tool Information**: Sets empty `informationUri` fields to `https://crowdstrike.com`
2. **Result Levels**: Normalizes severity levels to standard SARIF values (`error`, `warning`, `note`, `none`)
3. **Result Types**: Removes unsupported `type` properties from results
4. **Location Structure**: Ensures every result has a standardized locations array with URI set to `"unknown"`

### Why These Transformations Are Needed

These transformations resolve common GitHub SARIF parsing issues by:
- Ensuring all required fields meet GitHub's validation requirements
- Standardizing location structures to prevent parsing errors
- Normalizing severity levels for consistent GitHub Code Scanning integration

The transformations are applied automatically when SARIF format is requested and do not affect the scan results' accuracy or completeness.

## Support

This project is a community-driven, open source project designed to provide a simple way to run CrowdStrike Falcon Cloud Security (FCS) CLI in a GitHub Action.

While not a formal CrowdStrike product, this project is maintained by CrowdStrike and supported in partnership with the open source developer community.

For additional support, please see the [SUPPORT](SUPPORT.md) file.

## License

See [LICENSE](LICENSE)
