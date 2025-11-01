#!/usr/bin/env python3
"""
CVE Database Module for BugHunter Pro
Integrates with NVD (National Vulnerability Database) public API
"""

import sqlite3
import requests
import logging
import time
import json
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CVERecord:
    """CVE record data structure"""
    cve_id: str
    description: str
    published_date: str
    last_modified_date: str
    cvss_v3_score: Optional[float] = None
    cvss_v3_severity: Optional[str] = None
    cvss_v2_score: Optional[float] = None
    cvss_v2_severity: Optional[str] = None
    cwe_id: Optional[str] = None
    references: Optional[str] = None  # JSON string
    vulnerable_products: Optional[str] = None  # JSON string
    exploit_available: int = 0


class CVEDatabase:
    """CVE Database Manager with NVD API integration"""
    
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_LIMIT_DELAY = 6.0  # 6 seconds between requests (no API key)
    RATE_LIMIT_WITH_KEY = 0.6  # 0.6 seconds with API key (5 req/30s = ~0.6s)
    
    def __init__(self, database_path: str = "database/cve_database.db", api_key: Optional[str] = None):
        """
        Initialize CVE Database
        
        Args:
            database_path: Path to SQLite database
            api_key: NVD API key (optional, increases rate limit)
        """
        self.database_path = database_path
        self.api_key = api_key
        self.rate_limit_delay = self.RATE_LIMIT_WITH_KEY if api_key else self.RATE_LIMIT_DELAY
        self.last_request_time = 0
        self._ensure_database()
        
        logger.info(f"CVE Database initialized: {database_path}")
        if api_key:
            logger.info("Using NVD API key (faster rate limit)")
    
    def _ensure_database(self):
        """Ensure database and tables exist"""
        db_path = Path(self.database_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database with schema
        schema_path = Path(__file__).parent.parent / "database" / "schema.sql"
        
        if schema_path.exists():
            with open(schema_path, 'r') as f:
                schema_sql = f.read()
            
            conn = sqlite3.connect(self.database_path)
            try:
                conn.executescript(schema_sql)
                conn.commit()
                logger.info("Database schema initialized")
            except Exception as e:
                logger.error(f"Failed to initialize schema: {e}")
            finally:
                conn.close()
        else:
            logger.warning(f"Schema file not found: {schema_path}")
    
    def _rate_limit(self):
        """Apply rate limiting to NVD API requests"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - elapsed
            logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        self.last_request_time = time.time()
    
    def _make_nvd_request(self, params: Dict[str, Any]) -> Optional[Dict]:
        """
        Make request to NVD API with rate limiting
        
        Args:
            params: Query parameters
        
        Returns:
            API response as dict or None
        """
        self._rate_limit()
        
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        try:
            response = requests.get(
                self.NVD_API_BASE,
                params=params,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 403:
                logger.error("NVD API rate limit exceeded or invalid API key")
                return None
            else:
                logger.error(f"NVD API error: {response.status_code}")
                return None
        
        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
            return None
    
    def fetch_cve(self, cve_id: str) -> Optional[CVERecord]:
        """
        Fetch a single CVE from NVD API
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)
        
        Returns:
            CVERecord or None
        """
        logger.info(f"Fetching CVE: {cve_id}")
        
        params = {'cveId': cve_id}
        data = self._make_nvd_request(params)
        
        if not data or 'vulnerabilities' not in data:
            return None
        
        vulnerabilities = data['vulnerabilities']
        if not vulnerabilities:
            logger.warning(f"CVE not found: {cve_id}")
            return None
        
        return self._parse_cve_data(vulnerabilities[0])
    
    def _parse_cve_data(self, vuln_data: Dict) -> Optional[CVERecord]:
        """
        Parse CVE data from NVD API response
        
        Args:
            vuln_data: Vulnerability data from API
        
        Returns:
            CVERecord or None
        """
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', '')
            
            # Description
            descriptions = cve.get('descriptions', [])
            description = next(
                (d['value'] for d in descriptions if d['lang'] == 'en'),
                ''
            )
            
            # Dates
            published = cve.get('published', '')
            modified = cve.get('lastModified', '')
            
            # CVSS scores
            metrics = cve.get('metrics', {})
            cvss_v3_score = None
            cvss_v3_severity = None
            cvss_v2_score = None
            cvss_v2_severity = None
            
            # CVSS v3
            if 'cvssMetricV31' in metrics:
                cvss_v3 = metrics['cvssMetricV31'][0]['cvssData']
                cvss_v3_score = cvss_v3.get('baseScore')
                cvss_v3_severity = cvss_v3.get('baseSeverity', '').upper()
            elif 'cvssMetricV30' in metrics:
                cvss_v3 = metrics['cvssMetricV30'][0]['cvssData']
                cvss_v3_score = cvss_v3.get('baseScore')
                cvss_v3_severity = cvss_v3.get('baseSeverity', '').upper()
            
            # CVSS v2
            if 'cvssMetricV2' in metrics:
                cvss_v2 = metrics['cvssMetricV2'][0]['cvssData']
                cvss_v2_score = cvss_v2.get('baseScore')
                cvss_v2_severity = metrics['cvssMetricV2'][0].get('baseSeverity', '').upper()
            
            # CWE
            weaknesses = cve.get('weaknesses', [])
            cwe_id = None
            if weaknesses:
                cwe_data = weaknesses[0].get('description', [])
                if cwe_data:
                    cwe_id = cwe_data[0].get('value', '')
            
            # References
            references = []
            for ref in cve.get('references', []):
                references.append({
                    'url': ref.get('url', ''),
                    'source': ref.get('source', ''),
                    'tags': ref.get('tags', [])
                })
            
            # Vulnerable products (CPE)
            configurations = cve.get('configurations', [])
            vulnerable_products = []
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if cpe_match.get('vulnerable'):
                            vulnerable_products.append({
                                'cpe': cpe_match.get('criteria', ''),
                                'version_start': cpe_match.get('versionStartIncluding'),
                                'version_end': cpe_match.get('versionEndIncluding')
                            })
            
            return CVERecord(
                cve_id=cve_id,
                description=description,
                published_date=published,
                last_modified_date=modified,
                cvss_v3_score=cvss_v3_score,
                cvss_v3_severity=cvss_v3_severity,
                cvss_v2_score=cvss_v2_score,
                cvss_v2_severity=cvss_v2_severity,
                cwe_id=cwe_id,
                references=json.dumps(references),
                vulnerable_products=json.dumps(vulnerable_products)
            )
        
        except Exception as e:
            logger.error(f"Failed to parse CVE data: {e}")
            return None
    
    def store_cve(self, cve: CVERecord) -> bool:
        """
        Store CVE in database
        
        Args:
            cve: CVERecord to store
        
        Returns:
            True if successful
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO cves (
                    cve_id, description, published_date, last_modified_date,
                    cvss_v3_score, cvss_v3_severity, cvss_v2_score, cvss_v2_severity,
                    cwe_id, references, vulnerable_products, exploit_available,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                cve.cve_id, cve.description, cve.published_date, cve.last_modified_date,
                cve.cvss_v3_score, cve.cvss_v3_severity, cve.cvss_v2_score, cve.cvss_v2_severity,
                cve.cwe_id, cve.references, cve.vulnerable_products, cve.exploit_available
            ))
            
            conn.commit()
            conn.close()
            
            logger.debug(f"Stored CVE: {cve.cve_id}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to store CVE {cve.cve_id}: {e}")
            return False
    
    def fetch_and_store_cve(self, cve_id: str) -> bool:
        """
        Fetch CVE from NVD and store in database
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            True if successful
        """
        cve = self.fetch_cve(cve_id)
        if cve:
            return self.store_cve(cve)
        return False
    
    def fetch_recent_cves(self, days: int = 30, max_results: int = 100) -> int:
        """
        Fetch recent CVEs from NVD
        
        Args:
            days: Number of days to look back
            max_results: Maximum number of CVEs to fetch
        
        Returns:
            Number of CVEs fetched and stored
        """
        logger.info(f"Fetching CVEs from last {days} days (max: {max_results})")
        
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
            'resultsPerPage': min(max_results, 2000)  # NVD max is 2000
        }
        
        data = self._make_nvd_request(params)
        
        if not data or 'vulnerabilities' not in data:
            logger.error("Failed to fetch recent CVEs")
            return 0
        
        vulnerabilities = data['vulnerabilities']
        stored_count = 0
        
        logger.info(f"Processing {len(vulnerabilities)} CVEs...")
        
        for vuln_data in vulnerabilities:
            cve = self._parse_cve_data(vuln_data)
            if cve and self.store_cve(cve):
                stored_count += 1
            
            # Progress update every 10 CVEs
            if stored_count % 10 == 0:
                logger.info(f"  Stored {stored_count}/{len(vulnerabilities)} CVEs")
        
        logger.info(f"✅ Stored {stored_count} CVEs")
        return stored_count
    
    def search_cves(
        self,
        keyword: Optional[str] = None,
        severity: Optional[str] = None,
        cwe: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search CVEs in local database
        
        Args:
            keyword: Search in description
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
            cwe: Filter by CWE ID
            limit: Maximum results
        
        Returns:
            List of CVE records
        """
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM cves WHERE 1=1"
        params = []
        
        if keyword:
            query += " AND description LIKE ?"
            params.append(f"%{keyword}%")
        
        if severity:
            query += " AND cvss_v3_severity = ?"
            params.append(severity.upper())
        
        if cwe:
            query += " AND cwe_id = ?"
            params.append(cwe)
        
        query += " ORDER BY cvss_v3_score DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        results = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total CVEs
        cursor.execute("SELECT COUNT(*) FROM cves")
        stats['total_cves'] = cursor.fetchone()[0]
        
        # By severity
        cursor.execute("""
            SELECT cvss_v3_severity, COUNT(*) 
            FROM cves 
            WHERE cvss_v3_severity IS NOT NULL
            GROUP BY cvss_v3_severity
        """)
        stats['by_severity'] = dict(cursor.fetchall())
        
        # With exploits
        cursor.execute("SELECT COUNT(*) FROM cves WHERE exploit_available = 1")
        stats['with_exploits'] = cursor.fetchone()[0]
        
        # Total exploits
        cursor.execute("SELECT COUNT(*) FROM exploits")
        stats['total_exploits'] = cursor.fetchone()[0]
        
        conn.close()
        return stats


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Initialize database
    db = CVEDatabase()
    
    # Fetch a specific CVE (Log4Shell as example)
    cve_id = "CVE-2021-44228"
    print(f"\nFetching {cve_id}...")
    if db.fetch_and_store_cve(cve_id):
        print(f"✅ Successfully fetched and stored {cve_id}")
    
    # Get stats
    stats = db.get_stats()
    print(f"\nDatabase Statistics:")
    print(f"  Total CVEs: {stats['total_cves']}")
    print(f"  By Severity: {stats['by_severity']}")
    print(f"  With Exploits: {stats['with_exploits']}")
