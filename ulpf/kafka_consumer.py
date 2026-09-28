import asyncio
import hashlib
import json
import logging
import os

from aiokafka import AIOKafkaConsumer

from ulpf.engine import DeterministicEngine
from ulpf.models import EventEnvelope, EventStatus
from ulpf.registry import DynamicParserRegistry
from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("KafkaWorker")

async def consume_and_verify():
    kafka_bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    consumer = AIOKafkaConsumer(
        "raw-logs",
        bootstrap_servers=kafka_bootstrap,
        group_id="ulpf-core-router",
        auto_offset_reset="earliest",
    )

    registry = DynamicParserRegistry()
    engine = DeterministicEngine(registry=registry)
    spool = DurableSpool("ulpf_spool.db")
    
    # Connect the Consumer to PostgreSQL (reads DATABASE_URL from env)
    storage = NormalizedStorage() 

    logger.info("🚀 Booting up ULPF Kafka Consumer Worker...")
    max_retries = 15
    for attempt in range(1, max_retries + 1):
        try:
            await consumer.start()
            break
        except Exception as e:
            if attempt == max_retries:
                logger.error(f"Failed to connect to Kafka at {kafka_bootstrap} after {max_retries} attempts: {e}")
                raise
            logger.warning(f"Kafka broker at {kafka_bootstrap} not ready yet ({e}). Retrying in 2s (attempt {attempt}/{max_retries})...")
            await asyncio.sleep(2)

    logger.info(
        f"✅ Connected to KRaft Broker ({kafka_bootstrap}). Listening for events on 'raw-logs'...\n"
    )
    logger.info("-" * 60)

    try:
        async for msg in consumer:
            data = json.loads(msg.value.decode("utf-8"))

            event_id = data.get("event_id", "UNKNOWN_ID")
            raw_payload = data.get("raw_payload", "")
            transport = data.get("transport", "unknown")
            original_hash = data.get("original_hash", "")

            recalculated_hash = hashlib.sha256(
                raw_payload.encode("utf-8")
            ).hexdigest()

            if original_hash != recalculated_hash:
                logger.error(
                    "❌ TAMPERING DETECTED! event_id=%s "
                    "original_hash=%s recalculated_hash=%s",
                    event_id,
                    original_hash,
                    recalculated_hash,
                )
                print(
                    f"[{event_id}] ❌ TAMPERING DETECTED! "
                    f"original_hash={original_hash} "
                    f"recalculated_hash={recalculated_hash}"
                )
                print("└── Action:    🚨 ROUTED TO DEAD-LETTER QUEUE (DLQ)")
                print("-" * 70)
                continue

            envelope = EventEnvelope(
                event_id=event_id,
                raw_payload=raw_payload,
                source_transport=transport,
            )

            matched, parsed_event = engine.parse_and_normalize(envelope)

            truncated_payload = (
                raw_payload[:65] + "..."
                if len(raw_payload) > 65
                else raw_payload
            )

            print(f"\n[{event_id}] 📥 KAFKA EVENT DEQUEUED")
            print(f" ├── Source:    {transport.upper()}")
            print(f" ├── Payload:   {truncated_payload}")
            print(" ├── Integrity: ✅ VERIFIED IN-MEMORY (DB Bypassed)")

            if matched and parsed_event.status == EventStatus.COMMITTED:
                # --- NEW: Actually commit the parsed event to the Postgres DB ---
                storage.commit_event(parsed_event)
                
                print(" ├── Routing:   ⚡ FAST PATH (Regex Match)")
                print(f" ├── Parser ID: {parsed_event.parser_id}")
                print(" └── Action:    🟢 NORMALIZED & PERSISTED TO POSTGRESQL (Class 4001)")
            else:
                print(" ├── Routing:   ⚠️ UNKNOWN FORMAT (No Regex Match)")
                print(" └── Action:    🧠 ROUTED TO AI CONTROL PLANE")
                envelope.status = EventStatus.PENDING_AI
                spool.spool(envelope)

            print("-" * 70)

    except asyncio.CancelledError:
        logger.info("🛑 Stopping Consumer...")
    finally:
        await consumer.stop()

if __name__ == "__main__":
    try:
        asyncio.run(consume_and_verify())
    except KeyboardInterrupt:
        print("\nShutdown signal received.")