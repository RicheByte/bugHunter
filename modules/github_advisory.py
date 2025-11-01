#!/usr/bin/env python3
"""
GitHub Security Advisory Integration for BugHunter Pro
Integrates with GitHub Advisory Database API (public, no auth required)
"""

import requests
import sqlite3
import logging
import time
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class GitHubAdvisorySync:
    """GitHub Security Advisory database integration"""
    
    # GitHub Advisory Database API (public, REST)
    GITHUB_ADVISORY_API = "https://api.github.com/advisories"
    
    # GraphQL endpoint for more detailed queries (requires token for higher rate limit)
    GITHUB_GRAPHQL_API = "https://api.github.com/graphql"
    
    def __init__(
        self,
        database_path: str = "database/cve_database.db",
        github_token: Optional[str] = None
    ):
        """
        Initialize GitHub Advisory Sync
        
        Args:
            database_path: Path to SQLite database
            github_token: GitHub personal access token (optional, for higher rate limits)
        """
        self.database_path = database_path
        self.github_token = github_token
        self.session = requests.Session()
        
        if github_token:
            self.session.headers.update({
                'Authorization': f'token {github_token}'
            })
        
        self.session.headers.update({
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        })
        
        logger.info("GitHub Advisory Sync initialized")
    
    def fetch_advisories(
        self,
        ecosystem: Optional[str] = None,
        severity: Optional[str] = None,
        per_page: int = 30,
        max_pages: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Fetch advisories from GitHub
        
        Args:
            ecosystem: Filter by ecosystem (npm, pip, maven, etc.)
            severity: Filter by severity (critical, high, medium, low)
            per_page: Results per page (max 100)
            max_pages: Maximum pages to fetch
        
        Returns:
            List of advisory records
        """
        logger.info(f"Fetching GitHub advisories (ecosystem: {ecosystem}, severity: {severity})")
        
        advisories = []
        page = 1
        
        while page <= max_pages:
            params: Dict[str, Any] = {
                'per_page': min(per_page, 100),
                'page': page
            }
            
            if ecosystem:
                params['ecosystem'] = ecosystem
            
            if severity:
                params['severity'] = severity
            
            try:
                response = self.session.get(self.GITHUB_ADVISORY_API, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if not data:
                        break  # No more results
                    
                    advisories.extend(data)
                    logger.info(f"  Fetched page {page}: {len(data)} advisories")
                    
                    page += 1
                    time.sleep(1)  # Rate limiting
                
                elif response.status_code == 403:
                    logger.warning("GitHub API rate limit exceeded")
                    break
                
                else:
                    logger.error(f"GitHub API error: {response.status_code}")
                    break
            
            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed: {e}")
                break
        
        logger.info(f"✅ Fetched {len(advisories)} advisories total")
        return advisories
    
    def parse_advisory(self, advisory: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse GitHub advisory data
        
        Args:
            advisory: Raw advisory data from GitHub API
        
        Returns:
            Parsed exploit record or None
        """
        try:
            ghsa_id = advisory.get('ghsa_id', '')
            cve_id = advisory.get('cve_id')  # May be None
            
            # Get affected packages
            vulnerabilities = advisory.get('vulnerabilities', [])
            affected_packages = []
            
            for vuln in vulnerabilities:
                package = vuln.get('package', {})
                affected_packages.append({
                    'ecosystem': package.get('ecosystem'),
                    'name': package.get('name'),
                    'vulnerable_versions': vuln.get('vulnerable_version_range'),
                    'patched_versions': vuln.get('patched_versions')
                })
            
            # Get CVSS score
            cvss_score = None
            cvss_severity = advisory.get('severity', '').upper()
            
            if 'cvss' in advisory:
                cvss_score = advisory['cvss'].get('score')
            
            parsed = {
                'exploit_id': ghsa_id,
                'cve_id': cve_id,
                'title': advisory.get('summary', ''),
                'description': advisory.get('description', ''),
                'type': 'security_advisory',
                'platform': advisory.get('ecosystem', ''),
                'exploit_date': advisory.get('published_at', ''),
                'verified': 1,  # GitHub advisories are verified
                'source': 'github_advisory',
                'source_url': advisory.get('html_url', ''),
                'severity': cvss_severity,
                'cvss_score': cvss_score,
                'affected_packages': affected_packages,
                'references': advisory.get('references', [])
            }
            
            return parsed
        
        except Exception as e:
            logger.debug(f"Failed to parse advisory: {e}")
            return None
    
    def store_advisory(self, advisory: Dict[str, Any]) -> bool:
        """
        Store advisory as exploit in database
        
        Args:
            advisory: Parsed advisory dictionary
        
        Returns:
            True if successful
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            # Store as exploit
            cursor.execute('''
                INSERT OR REPLACE INTO exploits (
                    exploit_id, cve_id, title, description, type, platform,
                    exploit_date, verified, source, source_url,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                advisory['exploit_id'],
                advisory['cve_id'],
                advisory['title'],
                advisory['description'][:500],  # Truncate long descriptions
                advisory['type'],
                advisory['platform'],
                advisory['exploit_date'],
                advisory['verified'],
                advisory['source'],
                advisory['source_url']
            ))
            
            # Mark CVE if exists
            if advisory['cve_id']:
                cursor.execute('''
                    UPDATE cves
                    SET exploit_available = 1
                    WHERE cve_id = ?
                ''', (advisory['cve_id'],))
            
            conn.commit()
            conn.close()
            
            return True
        
        except Exception as e:
            logger.debug(f"Failed to store advisory {advisory['exploit_id']}: {e}")
            return False
    
    def sync_advisories(
        self,
        ecosystems: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
        max_per_query: int = 100
    ) -> Dict[str, Any]:
        """
        Sync GitHub advisories
        
        Args:
            ecosystems: List of ecosystems to sync (npm, pip, maven, etc.)
            severities: List of severities (critical, high, medium, low)
            max_per_query: Maximum advisories per query
        
        Returns:
            Sync result dictionary
        """
        logger.info("Starting GitHub Advisory synchronization")
        start_time = time.time()
        
        # Default ecosystems if not specified
        if not ecosystems:
            ecosystems = ['npm', 'pip', 'maven', 'nuget', 'composer', 'rubygems', 'go']
        
        all_advisories = []
        
        # Fetch for each ecosystem
        for ecosystem in ecosystems:
            logger.info(f"Fetching {ecosystem} advisories...")
            
            if severities:
                for severity in severities:
                    advisories = self.fetch_advisories(
                        ecosystem=ecosystem,
                        severity=severity,
                        per_page=30,
                        max_pages=3
                    )
                    all_advisories.extend(advisories)
            else:
                advisories = self.fetch_advisories(
                    ecosystem=ecosystem,
                    per_page=30,
                    max_pages=3
                )
                all_advisories.extend(advisories)
        
        # Remove duplicates
        unique_advisories = {adv['ghsa_id']: adv for adv in all_advisories}
        all_advisories = list(unique_advisories.values())
        
        logger.info(f"Processing {len(all_advisories)} unique advisories...")
        
        # Store advisories
        stored_count = 0
        failed_count = 0
        
        for advisory_data in all_advisories:
            advisory = self.parse_advisory(advisory_data)
            
            if advisory and self.store_advisory(advisory):
                stored_count += 1
            else:
                failed_count += 1
            
            # Progress update
            if (stored_count + failed_count) % 50 == 0:
                logger.info(f"  Progress: {stored_count + failed_count}/{len(all_advisories)}")
        
        duration = time.time() - start_time
        
        # Update sync metadata
        self._update_sync_metadata(
            status='success' if failed_count == 0 else 'partial',
            records_synced=stored_count,
            records_failed=failed_count,
            duration=duration
        )
        
        logger.info(f"✅ GitHub Advisory sync completed: {stored_count} stored, {failed_count} failed in {duration:.2f}s")
        
        return {
            'status': 'success',
            'total': len(all_advisories),
            'stored': stored_count,
            'failed': failed_count,
            'duration': duration
        }
    
    def _update_sync_metadata(
        self,
        status: str,
        records_synced: int = 0,
        records_failed: int = 0,
        duration: float = 0.0
    ):
        """Update sync metadata in database"""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO sync_metadata (
                    source, last_sync_time, last_sync_status,
                    records_synced, records_updated, records_failed,
                    sync_duration, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                'github_advisory',
                datetime.utcnow().isoformat(),
                status,
                records_synced,
                records_synced,
                records_failed,
                duration
            ))
            
            conn.commit()
            conn.close()
        
        except Exception as e:
            logger.error(f"Failed to update sync metadata: {e}")
    
    def search_advisories_by_package(
        self,
        package_name: str,
        ecosystem: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search advisories affecting a specific package
        
        Args:
            package_name: Package name to search
            ecosystem: Ecosystem filter (optional)
        
        Returns:
            List of matching advisories
        """
        try:
            conn = sqlite3.connect(self.database_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = """
                SELECT * FROM exploits 
                WHERE source = 'github_advisory'
                AND title LIKE ?
            """
            params = [f"%{package_name}%"]
            
            if ecosystem:
                query += " AND platform = ?"
                params.append(ecosystem)
            
            query += " ORDER BY exploit_date DESC"
            
            cursor.execute(query, params)
            results = [dict(row) for row in cursor.fetchall()]
            
            conn.close()
            return results
        
        except Exception as e:
            logger.error(f"Failed to search advisories: {e}")
            return []


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    print("\n" + "="*70)
    print("GitHub Security Advisory Integration Demo")
    print("="*70)
    
    # Initialize
    gh_advisory = GitHubAdvisorySync()
    
    # Sync advisories (subset for demo)
    print("\n📥 Syncing GitHub Security Advisories...")
    print("   Fetching from: npm, pip, maven")
    print("   Severity: critical, high\n")
    
    result = gh_advisory.sync_advisories(
        ecosystems=['npm', 'pip'],
        severities=['critical', 'high'],
        max_per_query=100
    )
    
    print(f"\nSync Result:")
    print(f"  Status: {result['status']}")
    print(f"  Total: {result.get('total', 0)}")
    print(f"  Stored: {result.get('stored', 0)}")
    print(f"  Failed: {result.get('failed', 0)}")
    print(f"  Duration: {result['duration']:.2f}s")
    
    # Search example
    print("\n🔍 Searching for advisories affecting 'express'...")
    results = gh_advisory.search_advisories_by_package('express', ecosystem='npm')
    
    print(f"\nFound {len(results)} advisories:")
    for adv in results[:3]:
        print(f"\n  ID: {adv['exploit_id']}")
        print(f"  Title: {adv['title'][:60]}...")
        print(f"  CVE: {adv['cve_id'] or 'N/A'}")
        print(f"  Date: {adv['exploit_date']}")
        print(f"  URL: {adv['source_url']}")
    
    print("\n💡 Note: GitHub Advisory API has rate limits (60 req/hour without token)")
