import sqlite3
import json
import time
from typing import Dict, Any, List

class AuditDatabaseService:
    def __init__(self, db_path: str = "cloudsentinel_audit.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                instance_id TEXT,
                pre_score INTEGER,
                post_score INTEGER,
                compliance_standard TEXT,
                status TEXT,
                manifest TEXT
            )
        """)
        conn.commit()
        conn.close()

    def record_migration_event(self, instance_id: str, pre_score: int, post_score: int, compliance: str, status: str, manifest: Dict[str, Any]):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (timestamp, instance_id, pre_score, post_score, compliance_standard, status, manifest)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            time.strftime("%Y-%m-%d %H:%M:%S"),
            instance_id,
            pre_score,
            post_score,
            compliance,
            status,
            json.dumps(manifest)
        ))
        conn.commit()
        conn.close()

    def get_historical_logs(self) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, instance_id, pre_score, post_score, compliance_standard, status FROM audit_logs ORDER BY id DESC")
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                "timestamp": r[0],
                "instance_id": r[1],
                "pre_score": r[2],
                "post_score": r[3],
                "compliance": r[4],
                "status": r[5]
            }
            for r in rows
        ]