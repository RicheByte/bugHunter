#!/usr/bin/env python3
"""
CVE Synchronization Module for BugHunter Pro
Scheduled synchronization of CVE database from NVD API
"""

import sqlite3
import logging
import time
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from modules.cve_database import CVEDatabase

logger = logging.getLogger(__name__)


class CVESync:
    """Scheduled CVE synchronization manager"""
    
    def __init__(
        self,
        database_path: str = "database/cve_database.db",
        api_key: Optional[str] = None,
        auto_start: bool = False
    ):
        """
        Initialize CVE Sync
        
        Args:
            database_path: Path to SQLite database
            api_key: NVD API key (optional)
            auto_start: Auto-start scheduler
        """
        self.database_path = database_path
        self.cve_db = CVEDatabase(database_path, api_key)
        self.scheduler = BackgroundScheduler()
        self.is_running = False
        
        if auto_start:
            self.start()
        
        logger.info("CVE Sync initialized")
    
    def _update_sync_metadata(
        self,
        source: str,
        status: str,
        records_synced: int = 0,
        records_updated: int = 0,
        records_failed: int = 0,
        duration: float = 0.0,
        error_message: Optional[str] = None
    ):
        """
        Update sync metadata in database
        
        Args:
            source: Data source (nvd, exploitdb, etc.)
            status: Sync status (success, failed, partial)
            records_synced: Number of records synced
            records_updated: Number of records updated
            records_failed: Number of failed records
            duration: Sync duration in seconds
            error_message: Error message if failed
        """
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO sync_metadata (
                    source, last_sync_time, last_sync_status,
                    records_synced, records_updated, records_failed,
                    sync_duration, error_message, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                source, datetime.utcnow().isoformat(), status,
                records_synced, records_updated, records_failed,
                duration, error_message
            ))
            
            conn.commit()
            conn.close()
            
            logger.debug(f"Updated sync metadata for {source}")
        
        except Exception as e:
            logger.error(f"Failed to update sync metadata: {e}")
    
    def sync_recent_cves(self, days: int = 7, max_results: int = 100) -> Dict[str, Any]:
        """
        Sync recent CVEs from NVD
        
        Args:
            days: Number of days to look back
            max_results: Maximum CVEs to fetch
        
        Returns:
            Sync result dictionary
        """
        logger.info(f"Starting CVE sync (last {days} days, max {max_results} results)")
        
        start_time = time.time()
        source = "nvd"
        
        try:
            # Fetch recent CVEs
            records_synced = self.cve_db.fetch_recent_cves(days=days, max_results=max_results)
            
            duration = time.time() - start_time
            
            # Update metadata
            self._update_sync_metadata(
                source=source,
                status="success",
                records_synced=records_synced,
                records_updated=records_synced,  # All are updates/inserts
                duration=duration
            )
            
            logger.info(f"✅ CVE sync completed: {records_synced} records in {duration:.2f}s")
            
            return {
                'status': 'success',
                'records_synced': records_synced,
                'duration': duration,
                'source': source
            }
        
        except Exception as e:
            duration = time.time() - start_time
            error_msg = str(e)
            
            logger.error(f"CVE sync failed: {error_msg}")
            
            # Update metadata with failure
            self._update_sync_metadata(
                source=source,
                status="failed",
                records_failed=1,
                duration=duration,
                error_message=error_msg
            )
            
            return {
                'status': 'failed',
                'error': error_msg,
                'duration': duration,
                'source': source
            }
    
    def sync_specific_cves(self, cve_ids: list) -> Dict[str, Any]:
        """
        Sync specific CVEs by ID
        
        Args:
            cve_ids: List of CVE IDs to sync
        
        Returns:
            Sync result dictionary
        """
        logger.info(f"Syncing {len(cve_ids)} specific CVEs")
        
        start_time = time.time()
        success_count = 0
        failed_count = 0
        
        for cve_id in cve_ids:
            try:
                if self.cve_db.fetch_and_store_cve(cve_id):
                    success_count += 1
                else:
                    failed_count += 1
            except Exception as e:
                logger.error(f"Failed to sync {cve_id}: {e}")
                failed_count += 1
        
        duration = time.time() - start_time
        
        logger.info(f"Synced {success_count}/{len(cve_ids)} CVEs in {duration:.2f}s")
        
        return {
            'status': 'completed',
            'total': len(cve_ids),
            'success': success_count,
            'failed': failed_count,
            'duration': duration
        }
    
    def schedule_daily_sync(self, hour: int = 2, minute: int = 0, days: int = 7, max_results: int = 100):
        """
        Schedule daily CVE sync
        
        Args:
            hour: Hour to run (0-23)
            minute: Minute to run (0-59)
            days: Number of days to sync
            max_results: Maximum results per sync
        """
        job_id = 'daily_cve_sync'
        
        # Remove existing job if present
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)
        
        # Add new job
        self.scheduler.add_job(
            func=lambda: self.sync_recent_cves(days=days, max_results=max_results),
            trigger=CronTrigger(hour=hour, minute=minute),
            id=job_id,
            name='Daily CVE Sync',
            replace_existing=True
        )
        
        logger.info(f"Scheduled daily CVE sync at {hour:02d}:{minute:02d} UTC")
    
    def schedule_weekly_sync(self, day_of_week: str = 'mon', hour: int = 3, days: int = 30, max_results: int = 500):
        """
        Schedule weekly CVE sync
        
        Args:
            day_of_week: Day to run (mon, tue, wed, thu, fri, sat, sun)
            hour: Hour to run (0-23)
            days: Number of days to sync
            max_results: Maximum results per sync
        """
        job_id = 'weekly_cve_sync'
        
        # Remove existing job if present
        if self.scheduler.get_job(job_id):
            self.scheduler.remove_job(job_id)
        
        # Add new job
        self.scheduler.add_job(
            func=lambda: self.sync_recent_cves(days=days, max_results=max_results),
            trigger=CronTrigger(day_of_week=day_of_week, hour=hour),
            id=job_id,
            name='Weekly CVE Sync',
            replace_existing=True
        )
        
        logger.info(f"Scheduled weekly CVE sync on {day_of_week} at {hour:02d}:00 UTC")
    
    def start(self):
        """Start the scheduler"""
        if not self.is_running:
            self.scheduler.start()
            self.is_running = True
            logger.info("✅ CVE Sync scheduler started")
    
    def stop(self):
        """Stop the scheduler"""
        if self.is_running:
            self.scheduler.shutdown(wait=False)
            self.is_running = False
            logger.info("CVE Sync scheduler stopped")
    
    def run_now(self, days: int = 7, max_results: int = 100) -> Dict[str, Any]:
        """
        Run sync immediately
        
        Args:
            days: Number of days to sync
            max_results: Maximum results
        
        Returns:
            Sync result
        """
        logger.info("Running immediate CVE sync")
        return self.sync_recent_cves(days=days, max_results=max_results)
    
    def get_sync_status(self) -> Dict[str, Any]:
        """
        Get sync status from database
        
        Returns:
            Dictionary with sync status for all sources
        """
        try:
            conn = sqlite3.connect(self.database_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM sync_metadata
                ORDER BY updated_at DESC
            ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            status = {}
            for row in rows:
                source = row['source']
                status[source] = {
                    'last_sync_time': row['last_sync_time'],
                    'status': row['last_sync_status'],
                    'records_synced': row['records_synced'],
                    'records_updated': row['records_updated'],
                    'records_failed': row['records_failed'],
                    'duration': row['sync_duration'],
                    'error': row['error_message']
                }
            
            return status
        
        except Exception as e:
            logger.error(f"Failed to get sync status: {e}")
            return {}
    
    def get_scheduled_jobs(self) -> list:
        """
        Get list of scheduled jobs
        
        Returns:
            List of job information
        """
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                'id': job.id,
                'name': job.name,
                'next_run': job.next_run_time.isoformat() if job.next_run_time else None,
                'trigger': str(job.trigger)
            })
        return jobs


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    print("\n" + "="*70)
    print("CVE Sync Module Demo")
    print("="*70)
    
    # Initialize sync manager
    sync_manager = CVESync()
    
    # Run immediate sync (small batch for demo)
    print("\n📥 Running immediate sync...")
    result = sync_manager.run_now(days=7, max_results=10)
    
    print(f"\nSync Result:")
    print(f"  Status: {result['status']}")
    print(f"  Records: {result.get('records_synced', 0)}")
    print(f"  Duration: {result['duration']:.2f}s")
    
    # Schedule daily sync
    print("\n📅 Scheduling daily sync at 02:00 UTC...")
    sync_manager.schedule_daily_sync(hour=2, minute=0, days=7, max_results=100)
    
    # Schedule weekly sync
    print("📅 Scheduling weekly sync on Monday at 03:00 UTC...")
    sync_manager.schedule_weekly_sync(day_of_week='mon', hour=3, days=30, max_results=500)
    
    # Start scheduler
    sync_manager.start()
    
    # Show scheduled jobs
    print("\n📋 Scheduled Jobs:")
    for job in sync_manager.get_scheduled_jobs():
        print(f"  - {job['name']}: Next run at {job['next_run']}")
    
    # Get sync status
    print("\n📊 Sync Status:")
    status = sync_manager.get_sync_status()
    for source, info in status.items():
        print(f"\n  {source.upper()}:")
        print(f"    Last Sync: {info['last_sync_time']}")
        print(f"    Status: {info['status']}")
        print(f"    Records: {info['records_synced']}")
    
    print("\n✅ Demo complete! Scheduler is running in background.")
    print("(Press Ctrl+C to stop)\n")
    
    try:
        # Keep running for demo
        import time
        time.sleep(10)
    except KeyboardInterrupt:
        print("\n⚠️  Stopping scheduler...")
    finally:
        sync_manager.stop()
