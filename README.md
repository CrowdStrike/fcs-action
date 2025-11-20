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

| Scope | Permission |
|---------|-------------|
| Infrastructure as Code | *READ* & *WRITE* |
| Falcon Container CLI | *READ* & *WRITE* |
| Falcon Container Image | *READ* & *WRITE* |

### Create a GitHub Secret

This action relies on the environment variable `FALCON_CLIENT_SECRET` to authenticate with the CrowdStrike API.

Create a GitHub secret in your repository to store the CrowdStrike API Client secret created from the step above. For more information, see [Creating secrets for a repository](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions#creating-secrets-for-a-repository).

### FCS Action Support for FCS CLI Versions

| **FCS CLI Version** | **FCS Action Version** |
| ------------------- | ---------------------- |
| **`>= 2.0.0`**      | **`>= 2.0.0`**         |
| **`>= 1.0.0`** and **`< 2.0.0`**  | **`>= 1.1.0`** and **`< 2.0.0`** |
| **`< 1.0.0`**       | **`< 1.1.0`**          |

## Usage

To use this action in your workflow, add the following step:
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v2.0.2
  with:
    falcon_client_id: 'abcdefghijk123456789'
    falcon_region: 'us-1'
    path: './my-iac-directory'
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->

## Environment Variables

| Variable | Description | Required | Default | Example |
| -------- | ----------- | -------- | ------- | ------- |
| `FALCON_CLIENT_SECRET` | CrowdStrike API Client Secret | **Yes** | - | `${{ secrets.FALCON_CLIENT_SECRET }}` |

## Inputs

### Core Configuration

| Input | Description | Required | Default | Example/Values |
| ----- | ----------- | -------- | ------- | -------------- |
| `falcon_client_id` | CrowdStrike API Client ID | **Yes** | - | `${{ vars.FALCON_CLIENT_ID }}` |
| `falcon_region` | CrowdStrike API region | **Yes** | **us-1**| **Allowed values**:</br>us-1</br>us-2</br>eu-1</br>us-gov-1</br>us-gov-2 |
| `version` | FCS CLI tool version to use | No | uses the latest | `2.0.2` |
| `bin_path` | FCS binary installation path | No | `$RUNNER_TEMP` | `/custom/bin` |
| `install_python` | Install Python via `actions/setup-python` | No | `true` | **Allowed values**:</br>true</br>false |
| `scan_type` | Type of scan to perform | No | `iac` | **Allowed values**:</br>iac</br>image |

### Common Parameters

| Input | Description | Required | Default | Example/Values |
| ----- | ----------- | -------- | ------- | -------------- |
| `timeout` | Timeout for scan in seconds | No | `300` | `600` |
| `upload_results` | Upload to Falcon Console | No | `false` | **Allowed values**:</br>true</br>false |

<details>
<summary><strong>🛠️ IaC Scanning Parameters</strong> (Click to expand)</summary>

| Input | Description | Required | Default | Example/Values |
| ----- | ----------- | -------- | ------- | -------------- |
| `path` | Path to scan (file/dir/git repo) | No | - | `./dir`</br>`git::repo`</br>`file.tf` |
| `output_path` | Path to save scan results</br>**NOTE: Must be a directory** | No | `./` | `./scan-results` |
| `report_formats` | List of output formats for reports | No | `json` | **Allowed values**:</br>json, csv, junit, sarif |
| `config` | Path to configuration file | No | - | `./fcs-config.json` |
| `policy_rule` | IaC scanning policy rule | No | `local` | **Allowed values**:</br>local</br>default-iac-alert-rule |
| `timeout` | Scan timeout in seconds | No | `500` | `900` |
| `disable_secrets_scan` | Disable secrets scanning | No | `false` | **Allowed values**:</br>true</br>false |
| `project_owners` | Project owners to notify (max 5) | No | - | `john@example.com,jane@example.com` |

#### Filtering & Categorization

| Input | Description | Required | Default | Example/Values |
| ----- | ----------- | -------- | ------- | -------------- |
| `categories` | Include specified categories | No | - | See [Categories](#reference-categories) |
| `exclude_categories` | Exclude specified categories | No | - | See [Categories](#reference-categories) |
| `platforms` | Include specified platforms | No | - | See [Platforms](#reference-platforms) |
| `exclude_platforms` | Exclude specified platforms | No | - | See [Platforms](#reference-platforms) |
| `severities` | Include specified severities | No | - | **Allowed values**:</br>critical</br>high</br>medium</br>informational |
| `exclude_severities` | Exclude specified severities | No | - | **Allowed values**:</br>critical</br>high</br>medium</br>informational |
| `exclude_paths` | Exclude paths from scan | No | - | `./test/*,file.tf` |
| `fail_on` | Exit codes for severity levels | No | critical=1,</br>high=1,</br>medium=1,</br>informational=1 | `critical=5,high=10` |

</details>

<details>
<summary><strong>🐳 Image Scanning Parameters</strong> (Click to expand)</summary>

#### Basic Image Settings

| Input | Description | Required | Default | Example/Values |
| ----- | ----------- | -------- | ------- | -------------- |
| `image` | Container image to scan | **Yes*** | - | `nginx:latest`</br>`quay.io/org/app:v1.0` |
| `output_path` | File path to save scan results.</br>**NOTE: must be a file, not a directory.** | No |  | `./scan-results.json` |
| `report_formats` | A **single** output format for generated report | No | `json` | **Allowed values**:</br>**Image**: json, sarif, sbom-cylconedx |
| `socket` | Custom container engine socket | No | - | `unix:///var/run/docker.sock` |
| `platform` | Target platform (os/arch/variant) | No | `linux/amd64` | `linux/amd64`</br>`linux/arm64`</br>`windows/amd64` |
| `temp_dir` | Custom temp directory | No | - | `/local/tmp` |

#### Scan Mode Options

| Input | Description | Required | Default | Example/Values |
| ----- | ----------- | -------- | ------- | -------------- |
| `vulnerability_only` | Scan vulnerabilities only | No | `false` | **Allowed values**:</br>true</br>false |
| `sbom_only` | Generate SBOM only | No | `false` | **Allowed values**:</br>true</br>false |

#### Vulnerability Filtering

| Input | Description | Required | Default | Example/Values |
| ----- | ----------- | -------- | ------- | -------------- |
| `minimum_score` | Min CVSS score threshold | No | - | `0.0-10.0` |
| `minimum_severity` | Min vulnerability severity | No | - | **Allowed values**:</br>low</br>medium</br>high</br>critical |
| `minimum_exprt` | Min ExPRT rating | No | - | **Allowed values**:</br>low</br>medium</br>high</br>critical |
| `exclude_vulnerabilities` | Exclude vulnerability IDs | No | - | `CVE-2023-1234,CVE-2023-5678` |
| `vuln_fixable_only` | Exclude unfixable vulnerabilities | No | `false` | **Allowed values**:</br>true</br>false |

#### Detection & Display Options

| Input | Description | Required | Default | Example/Values |
| ----- | ----------- | -------- | ------- | -------------- |
| `minimum_detection_severity` | Min detection severity | No | - | **Allowed values**:</br>low</br>medium</br>high</br>critical |
| `report_sort_by` | Sort report by criteria | No | - | `severity/asc`</br>`score/desc`</br>`vulnerability/asc` |
| `show_full_description` | Show full vuln descriptions | No | `false` | **Allowed values**:</br>true</br>false |
| `show_full_detection_details` | Show full detection details | No | `false` | **Allowed values**:</br>true</br>false |
| `no_color` | Disable colored output | No | `false` | **Allowed values**:</br>true</br>false |

> **Note**: *Required only when `scan_type` is `image`

</details>

## Reference Values

<details>
<summary id="reference-categories"><strong>📋 Available Categories</strong> (Click to expand)</summary>

For use with `categories` and `exclude_categories` parameters:

- **Access Control** - Authentication, authorization, and access management
- **Availability** - High availability and disaster recovery configurations
- **Backup** - Data backup and recovery configurations
- **Best Practices** - General security and operational best practices
- **Build Process** - CI/CD and build pipeline security
- **Encryption** - Data encryption at rest and in transit
- **Insecure Configurations** - Misconfigurations that create security risks
- **Insecure Defaults** - Default settings that should be changed
- **Networking and Firewall** - Network security and firewall rules
- **Observability** - Logging, monitoring, and auditing
- **Resource Management** - Resource allocation and management
- **Secret Management** - Secrets, keys, and credential management
- **Supply-Chain** - Supply chain security concerns
- **Structure and Semantics** - Code structure and syntax issues

</details>

<details>
<summary id="reference-platforms"><strong>✅ Supported Platforms</strong> (Click to expand)</summary>

For use with `platforms` and `exclude_platforms` parameters:

- **Ansible** - Ansible playbooks and configurations
- **AzureResourceManager** - Azure ARM templates
- **CloudFormation** - AWS CloudFormation templates
- **Crossplane** - Crossplane configurations
- **DockerCompose** - Docker Compose files
- **Dockerfile** - Docker container definitions
- **GoogleDeploymentManager** - Google Cloud Deployment Manager
- **Kubernetes** - Kubernetes manifests and configurations
- **OpenAPI** - OpenAPI/Swagger specifications
- **Pulumi** - Pulumi infrastructure code
- **ServerlessFW** - Serverless Framework configurations
- **Terraform** - Terraform infrastructure code

</details>

## Outputs

| Output | Description |
| ------ | ----------- |
| `exit-code` | Exit code of the FCS CLI tool. Returns `0` on success, non-zero when vulnerabilities match `fail_on` criteria or scan errors occur |

## Controlling Pipeline Flow with FCS CLI Exit Codes

The FCS action provides an `exit-code` output that allows you to control whether your pipeline continues or stops based on scan results. This is useful when you want to conditionally run subsequent steps based on scan outcomes

### How Exit Codes Work

The exit code of the action should remain `0` which denotes a successful run of the action, while the output `exit-code` reflects the result of the FCS CLI scan:

- **`0`**: Scan completed successfully with no issues matching your `fail_on` criteria
- **Non-zero**: Scan found vulnerabilities/issues that match your `fail_on` criteria, or an error occurred

The exit code behavior is controlled by the `fail_on` parameter:

```yaml
# This configuration will cause the action to return a non-zero exit code
# if ANY vulnerabilities are found at these severity levels
fail_on: 'critical=1,high=1,medium=1,informational=1'
```

## Examples

### Basic scan of a local file
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v2.0.2
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
  uses: crowdstrike/fcs-action@v2.0.2
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
  uses: crowdstrike/fcs-action@v2.0.2
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
  uses: crowdstrike/fcs-action@v2.0.2
  id: fcs
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'eu-1'
    path: './cloudformation'
    report_formats: 'sarif'
    output_path: './scan-results.sarif'
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}

- name: Upload SARIF report to GitHub Code scanning
    uses: github/codeql-action/upload-sarif@v3
    if: steps.fcs.outputs.exit-code != 0
    with:
      sarif_file: ./scan-results.sarif
```
<!-- x-release-please-end -->

### Scan with exclusions and severity filtering
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v2.0.2
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
  uses: crowdstrike/fcs-action@v2.0.2
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

### Continue pipeline on zero exit code (no vulnerabilities match fail_on criteria)
<!-- x-release-please-start-version -->
```yaml
- name: Scan Container Image
  uses: crowdstrike/fcs-action@v2.0.2
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'us-1'
    scan_type: image
    image: nginx:latest
    output_path: './image-scan-results/'
    report_formats: json
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}

- name: Continue piepline to push image, etc
    if: steps.fcs.outputs.exit-code = 0
    ...
```
<!-- x-release-please-end -->

### Vulnerability-only image scan with filtering
<!-- x-release-please-start-version -->
```yaml
- name: Scan Image for Vulnerabilities Only
  uses: crowdstrike/fcs-action@v2.0.2
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
  uses: crowdstrike/fcs-action@v2.0.2
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
  uses: crowdstrike/fcs-action@v2.0.2
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
  uses: crowdstrike/fcs-action@v2.0.2
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
  uses: crowdstrike/fcs-action@v2.0.2
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
  uses: crowdstrike/fcs-action@v2.0.2
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
