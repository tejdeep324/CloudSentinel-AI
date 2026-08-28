import os
import sys
import sqlite3
import json
import time
from typing import List, Dict, Any, Optional

# Ensure project root is available in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class AuditDatabaseService:
    """Manages immutable persistence for workload migration events and compliance audits."""

    def __init__(self, db_path: str = "cloudsentinel_audit.db"):
        self.db_path = db_path
        self._is_in_memory = db_path == ":memory:"
        self._persistent_conn: Optional[sqlite3.Connection] = None
        
        # If in-memory, maintain a single persistent connection across operations
        if self._is_in_memory:
            self._persistent_conn = sqlite3.connect(":memory:")
            self._persistent_conn.row_factory = sqlite3.Row
            
        self._initialize_database()

    def _get_connection(self) -> sqlite3.Connection:
        if self._is_in_memory and self._persistent_conn is not None:
            return self._persistent_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _close_connection_if_not_memory(self, conn: sqlite3.Connection) -> None:
        if not self._is_in_memory:
            try:
                conn.close()
            except Exception:
                pass

    def _initialize_database(self) -> None:
        """Initializes SQLite schema for immutable migration records."""
        conn = self._get_connection()
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS migration_audits (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        instance_id TEXT NOT NULL,
                        pre_scan_score INTEGER NOT NULL,
                        post_scan_score INTEGER NOT NULL,
                        compliance_framework TEXT NOT NULL,
                        deployment_status TEXT NOT NULL,
                        golden_ami_id TEXT NOT NULL,
                        manifest_json TEXT NOT NULL
                    )
                """)
        finally:
            self._close_connection_if_not_memory(conn)

    def record_migration_event(
        self,
        instance_id: str,
        pre_score: int,
        post_score: int,
        compliance: str,
        status: str,
        manifest: Dict[str, Any]
    ) -> int:
        """Persists a new migration event and returns the row id."""
        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO migration_audits (
                        timestamp,
                        instance_id,
                        pre_scan_score,
                        post_scan_score,
                        compliance_framework,
                        deployment_status,
                        golden_ami_id,
                        manifest_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    time.strftime("%Y-%m-%d %H:%M:%S"),
                    instance_id,
                    pre_score,
                    post_score,
                    compliance,
                    status,
                    manifest.get("ami_id", "UNKNOWN"),
                    json.dumps(manifest)
                ))
                return int(cursor.lastrowid)
        finally:
            self._close_connection_if_not_memory(conn)

    def get_historical_logs(self) -> List[Dict[str, Any]]:
        """Retrieves all historical migration audit records."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    id,
                    timestamp,
                    instance_id,
                    pre_scan_score,
                    post_scan_score,
                    compliance_framework,
                    deployment_status,
                    golden_ami_id
                FROM migration_audits
                ORDER BY id DESC
            """)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            self._close_connection_if_not_memory(conn)

    def clear_database(self) -> None:
        """Utility for test fixtures to wipe the database."""
        conn = self._get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM migration_audits")
        finally:
            self._close_connection_if_not_memory(conn)

    def close(self) -> None:
        """Explicitly closes persistent in-memory connections if active."""
        if self._persistent_conn is not None:
            try:
                self._persistent_conn.close()
            except Exception:
                pass
            self._persistent_conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        """Destructor to ensure open connections are cleanly closed upon garbage collection."""
        self.close()