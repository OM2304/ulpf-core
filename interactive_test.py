from ulpf.coordinator import PipelineCoordinator
from ulpf.engine import DeterministicEngine
from ulpf.spool import DurableSpool
from ulpf.storage import NormalizedStorage


def main():
    spool = DurableSpool("live_demo_spool.db")
    storage = NormalizedStorage("live_demo_analytics.db")
    engine = DeterministicEngine()
    coordinator = PipelineCoordinator(spool=spool, engine=engine, storage=storage)

    print("=== ULPF Interactive Log Terminal ===")
    print("Paste any raw log line below (or type 'exit' to quit):\n")

    while True:
        try:
            raw_input = input("Raw Log > ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if raw_input.lower() in ["exit", "quit"]:
            break
        if not raw_input:
            continue

        envelope = coordinator.ingest_raw_event(raw_input)
        print(f"\n[1] DURABLY SPOOLED: Event ID = {envelope.event_id}")
        print(f"    Raw SHA-256 Hash = {envelope.raw_sha256}")

        stats = coordinator.process_pending_batch(batch_size=1)

        if stats["committed"] > 0:
            record = storage.get_event_by_id(envelope.event_id)
            print(f"[2] COMMITTED (Normalized to OCSF Class 4001):")
            print(f"    Parser Used : {record['parser_id']}")
            print(f"    Action      : {record['action']} -> Disposition: {record['disposition']}")
            print(f"    Source IP   : {record['src_ip']}:{record['src_port']}")
            print(f"    Dest IP     : {record['dst_ip']}:{record['dst_port']}")
            print(f"    Protocol    : {record['protocol']}")
        else:
            print(f"[2] UNRECOGNIZED FORMAT -> Safely flagged as PENDING_AI in spool database.\n")
        print("-" * 60)


if __name__ == "__main__":
    main()