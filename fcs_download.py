#!/usr/bin/env python3
"""
GitHub Action script to download FCS CLI using falconpy.
Replaces fcs-pull.sh to download FCS binary directly instead of from container.
"""

import os
import sys
import platform
import hashlib
import tarfile
import zipfile
from pathlib import Path
from typing import Optional, Dict, Any
import requests
from falconpy import Downloads


class FCSDownloader:
    """Class to handle FCS download operations for GitHub Actions."""

    # Region to API URL mapping
    REGION_MAP = {
        "us-1": "api.crowdstrike.com",
        "us-2": "api.us-2.crowdstrike.com",
        "eu-1": "api.eu-1.crowdstrike.com",
        "us-gov-1": "api.laggar.gcw.crowdstrike.com",
        "us-gov-2": "api.us-gov-2.crowdstrike.mil",
    }

    def __init__(self, client_id: str, client_secret: str, region: str):
        """Initialize the FCS downloader."""
        self.client_id = client_id
        self.client_secret = client_secret
        self.region = region
        self.api_url = self.REGION_MAP.get(region, "api.crowdstrike.com")
        # Initialize Downloads client
        self.downloads = Downloads(
            client_id=client_id, client_secret=client_secret, base_url=self.api_url
        )

    def detect_platform(self) -> str:
        """Detect the current platform for FCS download."""
        system = platform.system().lower()
        machine = platform.machine().lower()
        # Map Python platform detection to FCS platform names
        if system == "linux":
            if machine in ["aarch64", "arm64"]:
                return "linux-arm64"
            elif machine in ["x86_64", "amd64"]:
                return "linux-amd64"
        elif system == "darwin":
            if machine in ["arm64"]:
                return "darwin-arm64"
            elif machine in ["x86_64"]:
                return "darwin-amd64"
        elif system == "windows":
            if machine in ["aarch64", "arm64"]:
                return "windows-arm64"
            elif machine in ["x86_64", "amd64"]:
                return "windows-amd64"

        # Default fallback
        print(
            f"WARNING: Unknown platform {system}-{machine}, defaulting to linux-amd64"
        )
        return "linux-amd64"

    def get_available_fcs_files(self, platform: str) -> Optional[Dict[str, Any]]:
        """Get available FCS files for the specified platform."""
        try:
            response = self.downloads.enumerate(platform=platform, category="fcs")
            if response["status_code"] != 200:
                print(f"ERROR: Error enumerating files: {response}")
                return None
            return response["body"]
        except Exception as e:
            print(f"ERROR: Error querying FCS files: {e}")
            return None

    def find_version(
        self, files_data: Dict[str, Any], target_version: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Find the specified version or latest if not specified."""
        resources = files_data.get("resources", [])
        if not resources:
            print("ERROR: No resources found in the response")
            return None
        if target_version:
            # Look for the specific version
            for resource in resources:
                if resource.get("version") == target_version:
                    print(f"Found FCS {target_version}: {resource.get('file_name')}")
                    return resource
            # If target version not found, show available versions
            versions = [r.get("version") for r in resources if r.get("version")]
            print(
                f"ERROR: FCS {target_version} not found. Available versions: {versions}"
            )
            return None

        # Get the latest version
        if resources:
            try:
                # Sort by version number
                latest = max(
                    resources,
                    key=lambda x: [
                        int(v) for v in x.get("version", "0.0.0").split(".")
                    ],
                )
                print(
                    f"Using latest FCS version: {latest.get('version')} - {latest.get('file_name')}"
                )
                return latest
            except ValueError:
                # Fallback to first resource if version parsing fails
                latest = resources[0]
                print(
                    f"Using FCS version: {latest.get('version')} - {latest.get('file_name')}"
                )
                return latest
        return None

    def get_download_details(
        self, file_name: str, file_version: str
    ) -> Optional[Dict[str, Any]]:
        """Get download details including pre-signed URL and hash."""
        try:
            response = self.downloads.download(
                file_name=file_name, file_version=file_version
            )
            if response["status_code"] != 200:
                print(f"ERROR: Error getting download details: {response}")
                return None
            return response["body"]["resources"]
        except Exception as e:
            print(f"ERROR: Error getting download details: {e}")
            return None

    def download_file(
        self, download_url: str, file_name: str, expected_hash: str
    ) -> bool:
        """Download the file and validate its hash."""
        try:
            response = requests.get(download_url, stream=True)
            response.raise_for_status()
            with open(file_name, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            print(f"Downloaded {file_name}")
            # Validate hash
            return self.validate_file_hash(file_name, expected_hash)
        except Exception as e:
            print(f"ERROR: Download failed: {e}")
            return False

    def validate_file_hash(self, file_name: str, expected_hash: str) -> bool:
        """Validate the downloaded file's SHA256 hash."""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_name, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            file_hash = sha256_hash.hexdigest()
            if file_hash.lower() == expected_hash.lower():
                print("File hash validated successfully")
                return True
            else:
                print("ERROR: Hash mismatch!")
                print(f"Expected: {expected_hash}")
                print(f"Got:      {file_hash}")
                return False
        except Exception as e:
            print(f"ERROR: Hash validation failed: {e}")
            return False

    def extract_and_setup_fcs(self, file_name: str, bin_path: str) -> Optional[str]:
        """Extract FCS binary and set it up."""
        try:
            # Create bin directory
            Path(bin_path).mkdir(parents=True, exist_ok=True)
            # Extract based on file type
            if file_name.endswith(".tar.gz"):
                with tarfile.open(file_name, "r:gz") as tar:
                    # Find the fcs binary in the archive
                    for member in tar.getmembers():
                        if member.name.endswith("/fcs") or member.name == "fcs":
                            # Extract to our bin path
                            member.name = "fcs"  # Rename to just 'fcs'
                            tar.extract(member, bin_path)
                            break
            elif file_name.endswith(".zip"):
                with zipfile.ZipFile(file_name, "r") as zip_file:
                    # Find the fcs binary in the archive
                    for file_info in zip_file.filelist:
                        if (
                            file_info.filename.endswith("/fcs")
                            or file_info.filename.endswith("fcs.exe")
                            or file_info.filename == "fcs"
                        ):
                            # Extract to our bin path
                            extracted_name = (
                                "fcs.exe"
                                if file_info.filename.endswith(".exe")
                                else "fcs"
                            )
                            with (
                                zip_file.open(file_info) as source,
                                open(Path(bin_path) / extracted_name, "wb") as target,
                            ):
                                target.write(source.read())
                            break
            # Determine the binary name (Windows uses .exe)
            fcs_binary = "fcs.exe" if platform.system().lower() == "windows" else "fcs"
            fcs_path = Path(bin_path) / fcs_binary
            if not fcs_path.exists():
                print(f"ERROR: FCS binary not found after extraction: {fcs_path}")
                return None
            # Make executable on Unix-like systems
            if platform.system().lower() != "windows":
                os.chmod(fcs_path, 0o755)
            # Create log directory that FCS expects
            log_dir = Path.home() / ".crowdstrike" / "log"
            log_dir.mkdir(parents=True, exist_ok=True)
            print(f"Created log directory: {log_dir}")
            print(f"FCS binary ready at: {fcs_path}")
            return str(fcs_path)
        except Exception as e:
            print(f"ERROR: Extraction failed: {e}")
            return None

    def download_fcs(
        self,
        target_version: Optional[str] = None,
        bin_path: str = "/opt/crowdstrike/bin",
    ) -> Optional[str]:
        """Main method to download FCS."""
        # Step 1: Detect platform
        detected_platform = self.detect_platform()
        # Step 2: Get available files
        files_data = self.get_available_fcs_files(detected_platform)
        if not files_data:
            return None
        # Step 3: Find version
        file_info = self.find_version(files_data, target_version)
        if not file_info:
            return None
        file_name = file_info.get("file_name")
        file_version = file_info.get("version")
        # Step 4: Get download details
        download_details = self.get_download_details(file_name, file_version)
        if not download_details:
            return None
        download_url = download_details.get("download_url")
        expected_hash = download_details.get("file_hash")
        if not download_url or not expected_hash:
            print("ERROR: Missing download URL or file hash")
            return None
        # Step 5: Download and validate
        if not self.download_file(download_url, file_name, expected_hash):
            return None
        # Step 6: Extract and setup
        fcs_binary_path = self.extract_and_setup_fcs(file_name, bin_path)
        # Clean up downloaded archive
        try:
            os.remove(file_name)
            print(f"Cleaned up {file_name}")
        except Exception:
            pass
        return fcs_binary_path


def set_github_output(name: str, value: str):
    """Set GitHub Actions output variable."""
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"{name}={value}\n")
        print(f"Set GitHub output: {name}={value}")
    else:
        # Fallback for older runners
        print(f"::set-output name={name}::{value}")


def main():
    """Main function for GitHub Actions."""
    print("=" * 60)
    print("CrowdStrike FCS download with falconpy")
    print("=" * 60)
    # Get inputs from environment (GitHub Actions sets these)
    client_id = os.getenv("INPUT_FALCON_CLIENT_ID")
    client_secret = os.getenv(
        "FALCON_CLIENT_SECRET"
    )  # Set by workflow, not action input
    region = os.getenv("INPUT_FALCON_REGION", "us-1")
    version = os.getenv("INPUT_VERSION")  # Optional
    if not client_id:
        print("ERROR: INPUT_FALCON_CLIENT_ID environment variable is required")
        sys.exit(1)
    if not client_secret:
        print("ERROR: FALCON_CLIENT_SECRET environment variable is required")
        print("   This should be set by the workflow using:")
        print("   env:")
        print("     FALCON_CLIENT_SECRET: ${{ secrets.FALCON_CLIENT_SECRET }}")
        sys.exit(1)
    print("Configuration:")
    print(f"   Region: {region}")
    print(f"   Version: {version or 'latest'}")
    # Initialize downloader
    try:
        downloader = FCSDownloader(
            client_id=client_id,
            client_secret=client_secret,
            region=region,
        )
    except Exception as e:
        print(f"ERROR: Failed to initialize FCS downloader: {e}")
        sys.exit(1)
    # Download FCS
    bin_path = "/opt/crowdstrike/bin"
    fcs_binary_path = downloader.download_fcs(target_version=version, bin_path=bin_path)
    if fcs_binary_path:
        # Set GitHub Actions output
        set_github_output("FCS_BIN", fcs_binary_path)
        # Set for GitHub Actions
        github_path = os.getenv("GITHUB_PATH")
        if github_path:
            with open(github_path, "a") as f:
                f.write(f"{bin_path}\n")
        print("\nFCS download completed successfully!")
        print(f"FCS binary: {fcs_binary_path}")
        sys.exit(0)
    else:
        print("\nFCS download failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
