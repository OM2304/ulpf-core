import asyncio
import json
from aiokafka import AIOKafkaProducer

async def simulate_tampering():
    producer = AIOKafkaProducer(bootstrap_servers='localhost:9092')
    await producer.start()
    
    # The attacker alters the payload, but doesn't know how to perfectly spoof the ULPF hash
    msg = {
        "event_id": "ATTACK-9999",
        "raw_payload": "May 14 12:00:00 server sshd[1234]: Accepted password for root from 192.168.1.100 port 22 ssh2",
        "transport": "rogue_process",
        "original_hash": "deadbeefcafebabe1111222233334444555566667777888899990000aaaabbbb"
    }
    
    print("😈 INJECTING TAMPERED LOG INTO KAFKA...")
    await producer.send_and_wait("raw-logs", json.dumps(msg).encode('utf-8'))
    await producer.stop()
    print("✅ Malicious payload sent!")

if __name__ == "__main__":
    asyncio.run(simulate_tampering())