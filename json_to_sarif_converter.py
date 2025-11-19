#!/usr/bin/env python3
# pylint: disable=C0301,W1514
# flake8: noqa: E501
"""
Convert FCS scan JSON report to SARIF 2.1.0 format.
Supports both container image scans and Infrastructure as Code scans.
Ensures compliance with GitHub SARIF parsing requirements.
"""

import json
from typing import Dict, Any
from urllib.parse import quote


def encode_uri_for_github(uri_string: str) -> str:
    """
    Encode a string to be a valid URI for GitHub Code Scanning.
    
    GitHub has strict URI validation - colons cannot appear in the first path segment.
    This function URL-encodes problematic characters.
    """
    if not uri_string or uri_string == "unknown":
        return uri_string
    
    # URL encode the entire string to handle colons and other special characters
    # Use safe='' to encode everything, including '/' and ':'
    return quote(uri_string, safe='')


def filter_scan_data(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filter out top-level sections from scan data that cause GitHub upload failures.

    Args:
        scan_data: Original scan data dictionary

    Returns:
        Filtered scan data dictionary
    """
    # Top-level sections that cause GitHub upload failures
    excluded_sections = {
        'ImageInfo', 'ConfigInfo', 'OSInfo', 'InventoryEngineInfo',
        'Manifest', 'Config', 'imageinfo', 'configinfo', 'osinfo',
        'inventoryengineinfo', 'manifest', 'config'
    }

    # Create filtered scan data
    filtered_data = {}
    for key, value in scan_data.items():
        if key not in excluded_sections:
            filtered_data[key] = value

    return filtered_data


def convert_json_to_sarif(json_file_path: str, output_sarif_path: str) -> None:
    """
    Convert FCS JSON scan report to SARIF 2.1.0 format.

    Args:
        json_file_path: Path to the input JSON file
        output_sarif_path: Path where SARIF file will be written
    """
    with open(json_file_path, 'r') as f:
        scan_data = json.load(f)

    # Extract image name before filtering (since ImageInfo gets filtered out)
    image_name = extract_image_name(scan_data)

    # Filter out problematic top-level sections
    filtered_scan_data = filter_scan_data(scan_data)

    # Add the extracted image name back to filtered data
    if image_name != "unknown":
        filtered_scan_data['_extracted_image_name'] = image_name

    sarif_report = create_sarif_report(filtered_scan_data)

    with open(output_sarif_path, 'w') as f:
        json.dump(sarif_report, f, indent=2, sort_keys=True)


def extract_image_name(scan_data: Dict[str, Any]) -> str:
    """Extract image name from scan data before filtering."""
    image_info = scan_data.get('ImageInfo', {})
    if image_info:
        registry = image_info.get('Registry', '').replace('https://', '').replace('http://', '')
        repository = image_info.get('Repository', '')
        tag = image_info.get('Tag', '')
        if registry and repository and tag:
            if registry == 'index.docker.io':
                # Docker Hub shorthand
                return f"{repository}:{tag}"
            return f"{registry}/{repository}:{tag}"
        if repository and tag:
            # Handle case where registry might be empty but repo and tag exist
            return f"{repository}:{tag}"

    # Fallback to legacy format
    return scan_data.get('image_details', {}).get('full_image_name', 'unknown')


def create_sarif_report(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create SARIF 2.1.0 compliant report from scan data.

    Args:
        scan_data: Parsed JSON scan data

    Returns:
        SARIF report dictionary
    """
    # Detect scan type based on actual data structure
    scan_type = scan_data.get("scan_type", "")
    # Check for image scan indicators
    has_image_info = "ImageInfo" in scan_data

    is_iac_scan = (scan_type == "infrastructure_as_code" or
                   ("violations" in scan_data and not has_image_info) or
                   ("rule_detections" in scan_data and not has_image_info))

    # Set description based on scan type
    if is_iac_scan:
        short_desc = "Infrastructure as Code security scanner"
        full_desc = "Comprehensive security scanning for Infrastructure as Code including compliance checking, misconfiguration detection, secret scanning, and policy validation."
        artifact_desc = f"IaC Repository: {scan_data.get('repository_details', {}).get('name') or scan_data.get('path', 'unknown')}"
    else:
        short_desc = "Container image security scanner"
        full_desc = "Comprehensive security scanning for container images including vulnerability detection, secret scanning, malware detection, and misconfiguration analysis."

        # Use extracted image name if available, otherwise fallback to legacy method
        full_image_name = scan_data.get('_extracted_image_name', scan_data.get('image_details', {}).get('full_image_name', 'unknown'))

        artifact_desc = f"Container image: {full_image_name}"

    # Set artifact URI based on scan type
    if is_iac_scan:
        artifact_uri = scan_data.get('repository_details', {}).get('name') or scan_data.get('path', 'iac-scan')
    else:
        # Image scan - use extracted image name
        extracted_image_name = scan_data.get('_extracted_image_name', 'unknown')
        if extracted_image_name != 'unknown':
            artifact_uri = extracted_image_name
        else:
            artifact_uri = "container-image"

    # Create base SARIF structure
    sarif_report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CrowdStrike FCS",
                        "version": scan_data.get("scanner_version") or scan_data.get("fcs_version", "1.0.0"),
                        "informationUri": "https://crowdstrike.com",
                        "organization": "CrowdStrike",
                        "shortDescription": {
                            "text": short_desc
                        },
                        "fullDescription": {
                            "text": full_desc
                        },
                        "rules": []
                    }
                },
                "results": [],
                "artifacts": [
                    {
                        "location": {
                            "uri": encode_uri_for_github(artifact_uri)
                        },
                        "description": {
                            "text": artifact_desc
                        }
                    }
                ],
            }
        ]
    }

    # Get the run object for easier access
    run = sarif_report["runs"][0]

    # Convert different types of findings based on scan type
    if is_iac_scan:
        # Handle both formats: violations (legacy) and rule_detections (newer)
        if "violations" in scan_data:
            convert_iac_violations(scan_data, run)
        if "rule_detections" in scan_data:
            convert_rule_detections(scan_data, run)
        convert_iac_secrets(scan_data, run)
        convert_iac_policy_violations(scan_data, run)
    else:
        # Container image scan - use actual field names from the JSON
        convert_image_vulnerabilities(scan_data, run)
        convert_secrets(scan_data, run)  # Optional - may not be present
        convert_malware(scan_data, run)  # Optional - may not be present
        convert_image_detections(scan_data, run)  # Process Detections array
        convert_policy_response(scan_data, run)  # Process PolicyResponse

    return sarif_report


def convert_image_vulnerabilities(scan_data: Dict[str, Any], run: Dict[str, Any]) -> None:  # pylint: disable=R0914
    """Convert image vulnerability findings to SARIF results."""
    vulnerabilities = scan_data.get("Vulnerabilities", [])
    # Handle case where Vulnerabilities is explicitly set to null (e.g., with --vulnerability-only or other flags)
    if vulnerabilities is None:
        vulnerabilities = []

    for vuln_item in vulnerabilities:
        if vuln_item is None:
            continue

        vuln = vuln_item.get("Vulnerability", {}) if isinstance(vuln_item, dict) else {}
        if vuln is None:
            vuln = {}

        # Extract CVE ID
        cve_id = vuln.get("CVEID", "unknown") if vuln else "unknown"

        # Extract product information
        product = vuln.get("Product", {}) if vuln else {}
        if product is None:
            product = {}
        product_name = product.get("Product", "unknown") if isinstance(product, dict) else "unknown"
        product_version = product.get("MajorVersion", "unknown") if isinstance(product, dict) else "unknown"

        # Extract vulnerability details
        details = vuln.get("Details", {}) if vuln else {}
        if details is None:
            details = {}
        description = details.get("description", "No description available") if isinstance(details, dict) else "No description available"
        severity = details.get("severity", "MEDIUM") if isinstance(details, dict) else "MEDIUM"
        base_score = details.get("base_score", 0) if isinstance(details, dict) else 0
        vector = details.get("vector", "") if isinstance(details, dict) else ""
        published_date = details.get("published_date", "") if isinstance(details, dict) else ""

        # Extract fixed versions
        fixed_versions = vuln.get("FixedVersions", []) if vuln else []
        if fixed_versions is None:
            fixed_versions = []
        fixed_version = fixed_versions[0] if fixed_versions and len(fixed_versions) > 0 else "Not available"

        # Extract package source/path information
        package_source = product.get("PackageSource", product_name) if isinstance(product, dict) else product_name
        layer_hash = vuln.get("LayerHash", "") if vuln else ""

        # Create rule if not exists
        rule_id = f"vulnerability/{cve_id}"
        add_rule_if_not_exists(run, rule_id, {
            "id": rule_id,
            "name": cve_id,
            "shortDescription": {
                "text": f"Vulnerability: {cve_id}"
            },
            "fullDescription": {
                "text": description
            },
            "help": {
                "text": f"Package: {product_name} v{product_version}\nFixed version: {fixed_version}",
                "markdown": f"**Package:** {product_name} v{product_version}\n\n**Fixed version:** {fixed_version}\n\n**CVSS Score:** {base_score}\n\n**Layer:** {layer_hash[:12] if layer_hash else 'N/A'}"
            },
            "properties": {
                "tags": ["vulnerability", "security"],
                "precision": "high",
                "security-severity": str(base_score)
            }
        })

        # Create result
        result = {
            "ruleId": rule_id,
            "level": map_severity_to_level(severity),
            "message": {
                "text": f"{cve_id} in {product_name} v{product_version}: {description}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": encode_uri_for_github(package_source)
                        }
                    }
                }
            ],
            "properties": filter_github_safe_properties({
                "cvss_score": base_score,
                "cvss_vector": vector,
                "package_name": product_name,
                "package_version": product_version,
                "fixed_version": fixed_version,
                "published_date": published_date,
                "layer_hash": layer_hash,
                "exploited": details.get("exploited", {}).get("status") == 90 if "exploited" in details else False,
                "references": [ref.get("URL", "") for ref in details.get("references", [])],
                "cps_rating": details.get("cps_rating", {}).get("CurrentRating", {}).get("Rating", ""),
                "platform_type": product.get("PlatformType", "")
            })
        }

        run["results"].append(result)


def convert_vulnerabilities(scan_data: Dict[str, Any], run: Dict[str, Any]) -> None:
    """Convert vulnerability findings to SARIF results (legacy format)."""
    vulnerabilities = scan_data.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        # Create rule if not exists
        rule_id = f"vulnerability/{vuln.get('cve_id', 'unknown')}"
        add_rule_if_not_exists(run, rule_id, {
            "id": rule_id,
            "name": vuln.get('cve_id', 'Unknown Vulnerability'),
            "shortDescription": {
                "text": f"Vulnerability: {vuln.get('cve_id', 'Unknown')}"
            },
            "fullDescription": {
                "text": vuln.get('description', 'No description available')
            },
            "help": {
                "text": f"Package: {vuln.get('package_name', 'unknown')} v{vuln.get('package_version', 'unknown')}\nFixed version: {vuln.get('fixed_version', 'Not available')}",
                "markdown": f"**Package:** {vuln.get('package_name', 'unknown')} v{vuln.get('package_version', 'unknown')}\n\n**Fixed version:** {vuln.get('fixed_version', 'Not available')}\n\n**CVSS Score:** {vuln.get('cvss_score', 'N/A')}"
            },
            "properties": {
                "tags": ["vulnerability", "security"],
                "precision": "high"
            }
        })

        # Create result
        result = {
            "ruleId": rule_id,
            "level": map_severity_to_level(vuln.get('severity', 'medium')),
            "message": {
                "text": f"{vuln.get('cve_id', 'Unknown vulnerability')} in {vuln.get('package_name', 'unknown')} v{vuln.get('package_version', 'unknown')}: {vuln.get('description', 'No description')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "unknown"
                        }
                    }
                }
            ],
            "properties": filter_github_safe_properties({
                "cvss_score": vuln.get('cvss_score'),
                "cvss_vector": vuln.get('cvss_vector'),
                "package_name": vuln.get('package_name'),
                "package_version": vuln.get('package_version'),
                "fixed_version": vuln.get('fixed_version'),
                "exploitable": vuln.get('exploitable', False),
                "published_date": vuln.get('published_date'),
                "references": vuln.get('references', [])
            })
        }

        run["results"].append(result)


def convert_image_detections(scan_data: Dict[str, Any], run: Dict[str, Any]) -> None:  # pylint: disable=R0914
    """Convert image detection findings to SARIF results."""
    detections = scan_data.get("Detections", [])

    # Handle case where Detections is explicitly set to null (e.g., with --vulnerabilities-only)
    if detections is None:
        detections = []

    for detection_item in detections:
        if detection_item is None:
            continue

        detection = detection_item.get("Detection", {}) if isinstance(detection_item, dict) else {}
        if detection is None:
            detection = {}

        # Extract detection information
        detection_id = detection.get("ID", "unknown") if isinstance(detection, dict) else "unknown"
        detection_type = detection.get("Type", "unknown") if isinstance(detection, dict) else "unknown"
        detection_name = detection.get("Name", "unknown") if isinstance(detection, dict) else "unknown"
        title = detection.get("Title", "Unknown Detection") if isinstance(detection, dict) else "Unknown Detection"
        description = detection.get("Description", "No description available") if isinstance(detection, dict) else "No description available"
        remediation = detection.get("Remediation", "No remediation available") if isinstance(detection, dict) else "No remediation available"
        severity = detection.get("Severity", "Medium") if isinstance(detection, dict) else "Medium"
        details = detection.get("Details", {}) if isinstance(detection, dict) else {}
        if details is None:
            details = {}

        # Create rule ID based on type and name
        rule_id = f"{detection_type.lower()}/{detection_name}"

        # Set tags based on detection type
        tags = ["security"]
        if detection_type.lower() == "misconfiguration":
            tags.extend(["misconfiguration", "configuration"])
        elif detection_type.lower() == "cis":
            tags.extend(["cis", "compliance", "benchmark"])
        else:
            tags.append(detection_type.lower())

        add_rule_if_not_exists(run, rule_id, {
            "id": rule_id,
            "name": title,
            "shortDescription": {
                "text": title
            },
            "fullDescription": {
                "text": description
            },
            "help": {
                "text": remediation,
                "markdown": f"**Type:** {detection_type}\n\n**Remediation:** {remediation}"
            },
            "properties": {
                "tags": tags,
                "precision": "high"
            }
        })

        # Create result
        result = {
            "ruleId": rule_id,
            "level": map_severity_to_level(severity),
            "message": {
                "text": f"{title}: {description}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "container-image"
                        }
                    }
                }
            ],
            "properties": filter_github_safe_properties({
                "detection_id": detection_id,
                "detection_type": detection_type,
                "detection_name": detection_name,
                "remediation": remediation,
                "match": details.get("Match", ""),
                "severity": severity
            })
        }

        run["results"].append(result)


def convert_policy_response(scan_data: Dict[str, Any], run: Dict[str, Any]) -> None:
    """Convert policy response to SARIF results."""
    policy_response = scan_data.get("PolicyResponse", {})

    if not policy_response:
        return

    policy = policy_response.get("policy", {})
    policy_type = policy_response.get("policy_type", {})
    image = policy_response.get("image", {})
    deny = policy_response.get("deny", False)
    evaluated_at = policy_response.get("evaluated_at", "")

    # Only create a result if there's meaningful policy information
    if policy and (deny or policy.get("name")):
        rule_id = f"policy/{policy.get('uuid', 'unknown')}"

        add_rule_if_not_exists(run, rule_id, {
            "id": rule_id,
            "name": f"Policy Evaluation: {policy.get('name', 'Unknown Policy')}",
            "shortDescription": {
                "text": f"Policy evaluation for {policy_type.get('name', 'image policy')}"
            },
            "fullDescription": {
                "text": policy.get('description', 'Policy evaluation result for container image')
            },
            "properties": {
                "tags": ["policy", "compliance", "evaluation"],
                "precision": "high"
            }
        })

        # Determine level based on deny status
        level = "error" if deny else "note"

        # Build message
        status = "DENIED" if deny else "ALLOWED"
        message = f"Policy '{policy.get('name', 'Unknown')}' evaluation: {status}"

        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": message
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "container-image"
                        }
                    }
                }
            ],
            "properties": filter_github_safe_properties({
                "policy_uuid": policy.get("uuid"),
                "policy_name": policy.get("name"),
                "policy_description": policy.get("description"),
                "policy_type": policy_type.get("name"),
                "policy_version": policy_type.get("version"),
                "deny": deny,
                "evaluated_at": evaluated_at,
                "image_registry": image.get("registry"),
                "image_repository": image.get("repository"),
                "image_tag": image.get("tag"),
                "image_id": image.get("image_id"),
                "image_digest": image.get("image_digest")
            })
        }

        run["results"].append(result)


def convert_secrets(scan_data: Dict[str, Any], run: Dict[str, Any]) -> None:
    """Convert secret findings to SARIF results."""
    secrets = scan_data.get("secrets", [])
    # Handle case where secrets is explicitly set to null
    if secrets is None:
        secrets = []

    for secret in secrets:
        rule_id = f"secret/{secret.get('type', 'unknown')}"
        add_rule_if_not_exists(run, rule_id, {
            "id": rule_id,
            "name": f"Secret Detection: {secret.get('type', 'Unknown')}",
            "shortDescription": {
                "text": f"Potential {secret.get('type', 'secret')} detected"
            },
            "fullDescription": {
                "text": secret.get('description', 'Potential secret or sensitive information detected')
            },
            "properties": {
                "tags": ["secret", "security", "credentials"],
                "precision": "high"
            }
        })

        result = {
            "ruleId": rule_id,
            "level": map_severity_to_level(secret.get('severity', 'high')),
            "message": {
                "text": f"Potential {secret.get('type', 'secret')} found in {secret.get('file_path', 'unknown location')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "unknown"
                        }
                    }
                }
            ],
            "properties": filter_github_safe_properties({
                "file_path": secret.get('file_path'),
                "line_number": secret.get('line_number'),
                "confidence": secret.get('confidence'),
                "pattern_matched": secret.get('pattern_matched'),
                "entropy_score": secret.get('entropy_score')
            })
        }

        run["results"].append(result)


def convert_malware(scan_data: Dict[str, Any], run: Dict[str, Any]) -> None:
    """Convert malware findings to SARIF results."""
    malware_list = scan_data.get("malware", [])
    # Handle case where malware is explicitly set to null
    if malware_list is None:
        malware_list = []

    for malware in malware_list:
        rule_id = f"malware/{malware.get('type', 'unknown')}"
        add_rule_if_not_exists(run, rule_id, {
            "id": rule_id,
            "name": f"Malware Detection: {malware.get('name', 'Unknown')}",
            "shortDescription": {
                "text": f"Malware detected: {malware.get('type', 'unknown type')}"
            },
            "fullDescription": {
                "text": f"Malicious file detected: {malware.get('name', 'Unknown malware')}"
            },
            "properties": {
                "tags": ["malware", "security", "threat"],
                "precision": "high"
            }
        })

        result = {
            "ruleId": rule_id,
            "level": "error",  # Malware is always critical
            "message": {
                "text": f"Malware detected: {malware.get('name', 'Unknown')} ({malware.get('type', 'unknown type')}) in {malware.get('file_path', 'unknown location')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "unknown"
                        }
                    }
                }
            ],
            "properties": filter_github_safe_properties({
                "file_path": malware.get('file_path'),
                "file_hash": malware.get('file_hash'),
                "malware_type": malware.get('type'),
                "signature_name": malware.get('signature_name'),
                "confidence": malware.get('confidence')
            })
        }

        run["results"].append(result)


def convert_misconfigurations(scan_data: Dict[str, Any], run: Dict[str, Any]) -> None:
    """Convert misconfiguration findings to SARIF results."""
    misconfigs = scan_data.get("misconfigurations", [])

    for config in misconfigs:
        rule_id = f"misconfiguration/{config.get('rule_id', 'unknown')}"
        add_rule_if_not_exists(run, rule_id, {
            "id": rule_id,
            "name": config.get('title', 'Misconfiguration'),
            "shortDescription": {
                "text": config.get('title', 'Configuration issue detected')
            },
            "fullDescription": {
                "text": config.get('description', 'Configuration does not follow security best practices')
            },
            "help": {
                "text": config.get('remediation', 'Review and fix the configuration issue')
            },
            "properties": {
                "tags": ["misconfiguration", "security", config.get('category', 'general').lower()],
                "precision": "high"
            }
        })

        result = {
            "ruleId": rule_id,
            "level": map_severity_to_level(config.get('severity', 'medium')),
            "message": {
                "text": f"{config.get('title', 'Configuration issue')}: {config.get('description', 'See rule details')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "unknown"
                        }
                    }
                }
            ],
            "properties": filter_github_safe_properties({
                "category": config.get('category'),
                "framework": config.get('framework'),
                "file_path": config.get('file_path'),
                "line_number": config.get('line_number'),
                "remediation": config.get('remediation')
            })
        }

        run["results"].append(result)


def convert_policy_violations(scan_data: Dict[str, Any], run: Dict[str, Any]) -> None:
    """Convert policy violation findings to SARIF results."""
    violations = scan_data.get("policy_violations", [])

    for violation in violations:
        rule_id = f"policy/{violation.get('policy_id', 'unknown')}"
        add_rule_if_not_exists(run, rule_id, {
            "id": rule_id,
            "name": violation.get('policy_name', 'Policy Violation'),
            "shortDescription": {
                "text": f"Policy violation: {violation.get('violation_type', 'unknown')}"
            },
            "fullDescription": {
                "text": violation.get('description', 'Policy compliance violation detected')
            },
            "properties": {
                "tags": ["policy", "compliance"],
                "precision": "high"
            }
        })

        result = {
            "ruleId": rule_id,
            "level": map_severity_to_level(violation.get('severity', 'high')),
            "message": {
                "text": f"Policy violation: {violation.get('policy_name', 'Unknown policy')} - {violation.get('description', 'See policy details')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "unknown"
                        }
                    }
                }
            ],
            "properties": filter_github_safe_properties({
                "policy_id": violation.get('policy_id'),
                "policy_name": violation.get('policy_name'),
                "violation_type": violation.get('violation_type'),
                "action": violation.get('action')
            })
        }

        run["results"].append(result)


def convert_iac_violations(scan_data: Dict[str, Any], run: Dict[str, Any]) -> None:
    """Convert IaC violation findings to SARIF results."""
    violations = scan_data.get("violations", [])

    for violation in violations:
        # Create rule if not exists
        rule_id = f"iac/{violation.get('check_id', 'unknown')}"
        add_rule_if_not_exists(run, rule_id, {
            "id": rule_id,
            "name": violation.get('check_name', 'IaC Security Check'),
            "shortDescription": {
                "text": violation.get('check_name', 'Infrastructure as Code security violation')
            },
            "fullDescription": {
                "text": violation.get('description', 'No description available')
            },
            "help": {
                "text": violation.get('remediation', 'Review and fix the configuration issue'),
                "markdown": f"**Category:** {violation.get('category', 'Unknown')}\n\n**Remediation:** {violation.get('remediation', 'Review and fix the configuration issue')}\n\n**CWE:** {violation.get('cwe_id', 'N/A')}"
            },
            "properties": {
                "tags": ["iac", "security", violation.get('category', 'general').lower()],
                "precision": "high"
            }
        })

        # Create result
        file_details = violation.get('file_details', {})
        resource_details = violation.get('resource_details', {})

        result = {
            "ruleId": rule_id,
            "level": map_severity_to_level(violation.get('severity', 'medium')),
            "message": {
                "text": f"{violation.get('check_name', 'IaC violation')}: {violation.get('description', 'See rule details')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "unknown"
                        }
                    }
                }
            ],
            "properties": filter_github_safe_properties({
                "check_id": violation.get('check_id'),
                "check_type": violation.get('check_type'),
                "category": violation.get('category'),
                "subcategory": violation.get('subcategory'),
                "cwe_id": violation.get('cwe_id'),
                "owasp_category": violation.get('owasp_category'),
                "file_path": file_details.get('file_path'),
                "file_type": file_details.get('file_type'),
                "line_start": file_details.get('line_start'),
                "line_end": file_details.get('line_end'),
                "resource_type": resource_details.get('resource_type'),
                "resource_name": resource_details.get('resource_name'),
                "cloud_provider": resource_details.get('cloud_provider'),
                "service": resource_details.get('service'),
                "risk_score": violation.get('risk_assessment', {}).get('risk_score'),
                "compliance_mappings": violation.get('compliance_mappings', [])
            })
        }

        run["results"].append(result)


def convert_iac_secrets(scan_data: Dict[str, Any], run: Dict[str, Any]) -> None:
    """Convert IaC secret findings to SARIF results."""
    secrets_analysis = scan_data.get("secrets_analysis", {})
    secrets = secrets_analysis.get("secrets", [])

    for secret in secrets:
        rule_id = f"secret/{secret.get('type', 'unknown')}"
        add_rule_if_not_exists(run, rule_id, {
            "id": rule_id,
            "name": f"Secret Detection: {secret.get('type', 'Unknown')}",
            "shortDescription": {
                "text": f"Potential {secret.get('type', 'secret')} detected in IaC"
            },
            "fullDescription": {
                "text": "Potential secret or sensitive information detected in Infrastructure as Code files"
            },
            "help": {
                "text": secret.get('remediation', 'Use secure secret management solutions')
            },
            "properties": {
                "tags": ["secret", "security", "credentials", "iac"],
                "precision": "high"
            }
        })

        result = {
            "ruleId": rule_id,
            "level": "error",  # Secrets in IaC are always high severity
            "message": {
                "text": f"Potential {secret.get('type', 'secret')} found in {secret.get('file_path', 'unknown location')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "unknown"
                        }
                    }
                }
            ],
            "properties": filter_github_safe_properties({
                "file_path": secret.get('file_path'),
                "line_number": secret.get('line_number'),
                "confidence": secret.get('confidence'),
                "pattern_matched": secret.get('pattern_matched'),
                "entropy_score": secret.get('entropy_score'),
                "remediation": secret.get('remediation')
            })
        }

        run["results"].append(result)


def convert_rule_detections(scan_data: Dict[str, Any], run: Dict[str, Any]) -> None:
    """Convert rule detection findings to SARIF results (newer IaC format)."""
    rule_detections = scan_data.get("rule_detections", [])

    for rule_detection in rule_detections:
        rule_name = rule_detection.get('rule_name', 'Unknown Rule')
        rule_uuid = rule_detection.get('rule_uuid', 'unknown')
        rule_category = rule_detection.get('rule_category', 'General')
        description = rule_detection.get('description', 'No description available')
        severity = rule_detection.get('severity', 'Medium')
        platform = rule_detection.get('platform', 'Generic')
        cloud_provider = rule_detection.get('cloud_provider', 'General')
        service = rule_detection.get('service', '')
        rule_type = rule_detection.get('rule_type', '')

        detections = rule_detection.get('detections', [])

        for detection in detections:
            # Create rule if not exists
            rule_id = f"iac/{rule_uuid}"
            add_rule_if_not_exists(run, rule_id, {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {
                    "text": rule_name
                },
                "fullDescription": {
                    "text": description
                },
                "help": {
                    "text": detection.get('recommendation', 'Review and fix the configuration issue'),
                    "markdown": f"**Category:** {rule_category}\\n\\n**Platform:** {platform}\\n\\n**Cloud Provider:** {cloud_provider}\\n\\n**Recommendation:** {detection.get('recommendation', 'Review and fix the configuration issue')}"
                },
                "properties": {
                    "tags": ["iac", "security", rule_category.lower().replace(' ', '_')],
                    "precision": "high"
                }
            })

            # Create result
            result = {
                "ruleId": rule_id,
                "level": map_severity_to_level(severity),
                "message": {
                    "text": f"{rule_name}: {detection.get('reason', description)}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": encode_uri_for_github(detection.get('file', 'unknown'))
                            },
                            "region": {
                                "startLine": detection.get('line', 1)
                            }
                        }
                    }
                ],
                "properties": filter_github_safe_properties({
                    "rule_uuid": rule_uuid,
                    "rule_category": rule_category,
                    "platform": platform,
                    "cloud_provider": cloud_provider,
                    "service": service,
                    "rule_type": rule_type,
                    "file_path": detection.get('file'),
                    "line_number": detection.get('line'),
                    "file_sha256": detection.get('file_sha256'),
                    "issue_type": detection.get('issue_type'),
                    "reason": detection.get('reason'),
                    "recommendation": detection.get('recommendation'),
                    "resource_type": detection.get('resource_type'),
                    "resource_name": detection.get('resource_name')
                })
            }

            run["results"].append(result)


def convert_iac_policy_violations(scan_data: Dict[str, Any], run: Dict[str, Any]) -> None:
    """Convert IaC policy violation findings to SARIF results."""
    violations = scan_data.get("policy_violations", [])

    for violation in violations:
        rule_id = f"policy/{violation.get('policy_id', 'unknown')}"
        add_rule_if_not_exists(run, rule_id, {
            "id": rule_id,
            "name": violation.get('policy_name', 'IaC Policy Violation'),
            "shortDescription": {
                "text": f"IaC Policy violation: {violation.get('policy_type', 'unknown')}"
            },
            "fullDescription": {
                "text": violation.get('description', 'Infrastructure as Code policy compliance violation detected')
            },
            "properties": {
                "tags": ["policy", "compliance", "iac"],
                "precision": "high"
            }
        })

        result = {
            "ruleId": rule_id,
            "level": map_severity_to_level("medium"),  # Policy violations are typically medium
            "message": {
                "text": f"IaC Policy violation: {violation.get('policy_name', 'Unknown policy')} - {violation.get('description', 'See policy details')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": "unknown"
                        }
                    }
                }
            ],
            "properties": filter_github_safe_properties({
                "policy_id": violation.get('policy_id'),
                "policy_name": violation.get('policy_name'),
                "policy_type": violation.get('policy_type'),
                "violation_count": violation.get('violation_count'),
                "enforcement_level": violation.get('enforcement_level')
            })
        }

        run["results"].append(result)


def map_severity_to_level(severity: str) -> str:
    """
    Map severity strings to SARIF level values according to GitHub standards.

    Args:
        severity: Severity string from scan data

    Returns:
        SARIF level: "error", "warning", "note", or "none"
    """
    severity_lower = severity.lower() if severity else "medium"

    if severity_lower in ["critical", "high"]:
        return "error"
    if severity_lower in ["medium", "moderate"]:
        return "warning"
    if severity_lower in ["low", "info", "information", "negligible"]:
        return "note"
    if severity_lower in ["none", "unknown"]:
        return "none"
    return "note"  # Default fallback


def filter_github_safe_properties(properties: Dict[str, Any]) -> Dict[str, Any]:
    """
    Filter properties to only include those safe for GitHub SARIF upload.

    Args:
        properties: Original properties dictionary

    Returns:
        Filtered properties dictionary with only GitHub-safe properties
    """
    # Properties that are known to cause GitHub upload failures
    excluded_properties = {
        'imageinfo', 'configinfo', 'osinfo', 'inventoryengineinfo',
        'manifest', 'config', 'instance', 'image_details', 'container_info',
        'system_info', 'engine_info', 'scan_metadata', 'environment_info'
    }

    # Only keep safe properties
    safe_properties = {}
    for key, value in properties.items():
        if key.lower() not in excluded_properties and not any(excluded in key.lower() for excluded in excluded_properties):
            # Skip null/empty values
            if value is not None and value != "":
                safe_properties[key] = value

    return safe_properties


def add_rule_if_not_exists(run: Dict[str, Any], rule_id: str, rule_definition: Dict[str, Any]) -> None:
    """
    Add a rule to the SARIF run if it doesn't already exist.

    Args:
        run: SARIF run object
        rule_id: Rule identifier
        rule_definition: Rule definition dictionary
    """
    existing_rule_ids = {rule.get("id") for rule in run["tool"]["driver"]["rules"]}

    if rule_id not in existing_rule_ids:
        run["tool"]["driver"]["rules"].append(rule_definition)


def main():
    """Example usage of the converter."""
    import sys  # pylint: disable=C0415

    if len(sys.argv) != 3:
        print("Usage: python json_to_sarif_converter.py <input.json> <output.sarif>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    try:
        convert_json_to_sarif(input_file, output_file)
        print(f"Successfully converted {input_file} to {output_file}")
    except Exception as e:  # pylint: disable=W0718
        print(f"Error converting file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
