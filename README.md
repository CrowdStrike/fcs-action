# FCS CLI GitHub Action

This GitHub Action allows you to run the CrowdStrike Falcon Cloud Security (FCS) CLI tool directly in your CI/CD pipeline. Currently, the action supports scanning Infrastructure as Code (IaC) for misconfigurations and security vulnerabilities.

## Features

- Run FCS IaC scans on local files, directories, or Git repositories
- Customize scan parameters such as categories, platforms, and severities
- Generate scan reports in various formats
- Upload scan results to the CrowdStrike Falcon Console
- Flexible configuration options for tailoring the scan to your needs

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

## Usage

To use this action in your workflow, add the following step:
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v1.0.6
  with:
    falcon_client_id: 'abcdefghijk123456789'
    falcon_region: 'us-1'
    path: './my-iac-directory'
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->
## Environment Variables

| Variable | Description | Required | Default | Example/Allowed Values |
|----------|-------------|----------|---------|---------|
| `FALCON_CLIENT_SECRET` | CrowdStrike API Client Secret for authentication | **Yes** | - | `${{ secrets.FALCON_CLIENT_SECRET }}` |

## Inputs

| Input | Description | Required | Default                                        | Example/Allowed Values                                                                                                                                                                                                                                               |
|-------|-------------|----------|------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `falcon_client_id` | CrowdStrike API Client ID for authentication | **Yes** | -                                              | `${{ vars.FALCON_CLIENT_ID }}`                                                                                                                                                                                                                                       |
| `falcon_region` | CrowdStrike API region | **Yes** | `us-1`                                         | Allowed values: `us-1, us-2, eu-1, us-gov-1, us-gov-2`                                                                                                                                                                                                               |
| `version` | FCS CLI version to use | No | -                                              | `0.39.0`                                                                                                                                                                                                                                                             |
| `categories` | Include results for the specified categories, accepts a comma-separated list | No | -                                              | `Access Control,Best Practices`                                                                                                                                                                                                                                      |
| `config` | Path to the scan configuration file | No | -                                              | `./fcs-config.json`                                                                                                                                                                                                                                                  |
| `disable_secrets_scan` | Disable scanning of secrets and passwords in target files | No | `false`                                        | Allowed values: `true, false`                                                                                                                                                                                                                                        |
| `exclude_categories` | Exclude results for the specified categories, accepts a comma-separated list | No | -                                              | Allowed values: `Access Control, Availability, Backup, Best Practices, Build Process, Encryption, Insecure Configurations, Insecure Defaults, Networking and Firewall, Observability, Resource Management, Secret Management, Supply-Chain, Structure and Semantics` |
| `exclude_paths` | Exclude paths from scan | No | -                                              | `./sample-dir-to-omit/*,sample-file.tf`                                                                                                                                                                                                                              |
| `exclude_platforms` | Exclude results for the specified platforms, accepts a comma-separated list | No | -                                              | Allowed values: `Ansible, AzureResourceManager, Buildah, CloudFormation, Crossplane, DockerCompose, Dockerfile, GoogleDeploymentManager, Knative, Kubernetes, OpenAPI, Pulumi, ServerlessFW, Terraform`                                                              |
| `exclude_severities` | Exclude results for the specified severities, accepts a comma-separated list | No | -                                              | Allowed values: `critical, high, medium, informational`                                                                                                                                                                                                              |
| `fail_on` | Which kind of results should return a non-zero exit code, accepts a comma-separated list of `<severity>=<value>` | No | `critical=1, high=1,medium=1, informational=1` | `"high=2,medium=50"`                                                                                                                                                                                                                                                 |
| `output_path` | Path to save the scan results | No | `./`                                           | `./scan-results`                                                                                                                                                                                                                                                     |
| `path` | Path to local file, directory or git repo to scan | No | -                                              | `./my-local-dir, git::<git repo>, sample-file.tf`                                                                                                                                                                                                                    |
| `platforms` | Include results for the specified platforms, accepts a comma-separated list | No | -                                              | Allowed values: `Ansible, AzureResourceManager, Buildah, CloudFormation, Crossplane, DockerCompose, Dockerfile, GoogleDeploymentManager, Knative, Kubernetes, OpenAPI, Pulumi, ServerlessFW, Terraform`                                                              |
| `project_owners` | Comma-separated list of project owners to notify (max 5) | No | -                                              | `john@example.com,jane@example.com`                                                                                                                                                                                                                                  |
| `report_formats` | Formats in which reports are to be written, accepts a comma-separated list | No | `json`                                         | Allowed values: `json, csv, junit, sarif`                                                                                                                                                                                                                            |
| `severities` | Include results for the specified severities, accepts a comma-separated list | No | -                                              | Allowed values: `critical, high, medium, informational`                                                                                                                                                                                                                            |
| `timeout` | Timeout for the scan in seconds | No | `300`                                          | `900`                                                                                                                                                                                                                                                                |
| `upload_results` | Upload scan results to the CrowdStrike Falcon Console | No | `false`                                        | `true`                                                                                                                                                                                                                                                               |

## Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | Exit code of the FCS CLI tool |

## Examples

### Basic scan of a local file
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v1.0.6
  with:
    falcon_client_id: ${{ vars.FALCON_CLIENT_ID }}
    falcon_region: 'us-1'
    path: './sample-file.tf'
  env:
    FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}
```
<!-- x-release-please-end -->
### Upload SARIF report to GitHub Code scanning on non-zero exit code
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v1.0.6
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
    uses: github/codeql-action/upload-sarif@v2
    if: steps.fcs.outputs.exit-code != 0
    with:
      sarif_file: ./scan-results/*-scan-results.sarif
```
<!-- x-release-please-end -->
### Scan with exclusions and severity filtering
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v1.0.6
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
---

You can also use configuration files to customize the scan parameters. For more information, see the [FCS CLI documentation](https://falcon.crowdstrike.com/login/?unilogin=true&next=/documentation/page/e08ea90a/infrastructure-as-code-security#u253ccc1)

### Run scan with configuration file
<!-- x-release-please-start-version -->
```yaml
- name: Run FCS IaC Scan
  uses: crowdstrike/fcs-action@v1.0.6
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

## Support

This project is a community-driven, open source project designed to provide a simple way to run CrowdStrike Falcon Cloud Security (FCS) CLI in a GitHub Action.

While not a formal CrowdStrike product, this project is maintained by CrowdStrike and supported in partnership with the open source developer community.

For additional support, please see the [SUPPORT](SUPPORT.md) file.

## License

See [LICENSE](LICENSE)
