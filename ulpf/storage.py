import json
import logging
import psycopg2
from typing import Any, Dict, List, Optional
from psycopg2.extras import RealDictCursor
from ulpf.models import EventEnvelope, EventStatus

logger = logging.getLogger("PostgresStorage")

class NormalizedStorage:
    def __init__(self, db_path_ignored: str = None):
        self.db_password = "root"  # <--- Kept your password intact
        
        self.conn_params = {
            "dbname": "postgres", 
            "user": "postgres",
            "password": self.db_password,
            "host": "localhost",
            "port": "5432"
        }
        self._initialize_db()

    def _get_connection(self):
        return psycopg2.connect(**self.conn_params)

    def _initialize_db(self) -> None:
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS ocsf_ledger (
                            id SERIAL PRIMARY KEY,
                            event_id VARCHAR(255) UNIQUE NOT NULL,
                            class_uid VARCHAR(50) NOT NULL,
                            parser_id VARCHAR(100),
                            raw_payload TEXT,
                            normalized_data JSONB,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """)
                conn.commit()
            logger.info("🐘 PostgreSQL Immutable Ledger connected and verified.")
        except Exception as e:
            logger.error(f"❌ PostgreSQL Connection Failed. Error: {e}")

    def commit_event(self, envelope) -> bool:
        # 1. Corrected status check
        if envelope.status != EventStatus.COMMITTED or not getattr(envelope, "ocsf_event", None):
            return False

        # 2. Safely extract the OCSF JSON dictionary just like the old SQLite version did
        ocsf = envelope.ocsf_event
        if hasattr(ocsf, "model_dump"):
            ocsf_dict = ocsf.model_dump()
        elif hasattr(ocsf, "dict"):
            ocsf_dict = ocsf.dict()
        elif isinstance(ocsf, dict):
            ocsf_dict = ocsf
        else:
            ocsf_dict = {}

        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO ocsf_ledger 
                        (event_id, class_uid, parser_id, raw_payload, normalized_data)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (event_id) DO NOTHING;
                    """, (
                        envelope.event_id,
                        getattr(envelope, 'class_uid', '4001'),
                        envelope.parser_id,
                        envelope.raw_payload,
                        json.dumps(ocsf_dict)
                    ))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"❌ Failed to write to Ledger: {e}")
            return False

    def get_event_by_id(self, event_id: str) -> Optional[Dict]:
        with self._get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM ocsf_ledger WHERE event_id = %s", (event_id,))
                row = cur.fetchone()
                if row:
                    return dict(row)
        return None

    def list_events(
        self,
        limit: int = 50,
        offset: int = 0,
        disposition: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        
        query = """
            SELECT event_id, parser_id, raw_payload, normalized_data
            FROM ocsf_ledger
            ORDER BY id DESC LIMIT %s OFFSET %s
        """
        
        events: List[Dict[str, Any]] = []
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, (limit, offset))
                    rows = cur.fetchall()

            for row in rows:
                event_id, parser_id, raw_payload, normalized_data = row
                
                # Psycopg2 parses JSONB automatically into a dict
                event = normalized_data if isinstance(normalized_data, dict) else {}
                
                # Map back to the flat structure the React UI expects
                event.update({
                    "event_id": str(event_id),
                    "parser_id": str(parser_id or ""),
                    "raw_payload": str(raw_payload or ""),
                    "src_ip": str(event.get("src_endpoint", {}).get("ip", "")),
                    "dst_ip": str(event.get("dst_endpoint", {}).get("ip", "")),
                    "protocol": str(event.get("connection_info", {}).get("protocol_name", "")),
                    "action": str(event.get("action", "Unknown")),
                    "disposition": str(event.get("disposition", "Unknown"))
                })
                events.append(event)
        except Exception as e:
            logger.error(f"Failed to list events: {e}")
            
        return events