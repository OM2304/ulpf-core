import os
import json
import chromadb
from chromadb.utils import embedding_functions
from rich import print as rprint

def initialize_rag_database():
    rprint("[bold cyan]🚀 Initializing Enriched Offline RAG Vector Database...[/bold cyan]")
    
    db_path = os.path.join(os.getcwd(), "ulpf_chroma_db")
    client = chromadb.PersistentClient(path=db_path)
    emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
    
    try:
        client.delete_collection(name="log_parsers")
    except Exception:
        pass 
        
    collection = client.create_collection(name="log_parsers", embedding_function=emb_fn)

    # --- ENRICHED KNOWLEDGE BASE (NEW SEMANTIC PARSING PLANS) ---
    examples = [
        {
            "id": "net_iptables_1",
            "category": "NETWORK",
            "log": "Jan 16 06:25:14 inet-firewall kernel: [123.456] dmz-fw DROP IN=eth0 OUT= MAC=... SRC=192.168.1.50 DST=10.0.0.5 PROTO=TCP",
            "parsing_plan": json.dumps({
                "fields": [
                    {"val": "192.168.1.50", "field": "src_ip", "type": "IPV4"},
                    {"val": "10.0.0.5", "field": "dst_ip", "type": "IPV4"},
                    {"val": "TCP", "field": "proto", "type": "WORD"},
                    {"val": "DROP", "field": "action", "type": "ACTION"}
                ]
            }),
            "mappings": '{"src_ip": "src_ip", "dst_ip": "dst_ip", "proto": "proto", "action": "action"}'
        },
        {
            "id": "auth_pam_unix_1",
            "category": "AUTHENTICATION",
            "log": "Jan 16 06:25:14 intranet-server CRON[14139]: pam_unix(cron:session): session closed for user root",
            "parsing_plan": json.dumps({
                "fields": [
                    {"val": "closed", "field": "status", "type": "WORD"},
                    {"val": "root", "field": "user", "type": "WORD"}
                ]
            }),
            "mappings": '{"user": "user", "status": "status"}'
        },
        {
            "id": "web_apache_1",
            "category": "WEB",
            "log": "192.168.1.100 - - [16/Jan/2026:06:25:14 +0000] \"GET /index.html HTTP/1.1\" 200 1024",
            "parsing_plan": json.dumps({
                "fields": [
                    {"val": "192.168.1.100", "field": "src_ip", "type": "IPV4"},
                    {"val": "GET", "field": "method", "type": "WORD"},
                    {"val": "/index.html", "field": "url", "type": "PATH"},
                    {"val": "200", "field": "status", "type": "NUMBER"}
                ]
            }),
            "mappings": '{"src_ip": "src_ip", "method": "method", "url": "url", "status": "status"}'
        }
    ]

    collection.add(
        ids=[ex["id"] for ex in examples],
        documents=[ex["log"] for ex in examples],
        metadatas=[
            {"category": ex["category"], "parsing_plan": ex["parsing_plan"], "mappings": ex["mappings"]} 
            for ex in examples
        ]
    )
    
    rprint("[green]✓ Offline RAG Database enriched with Semantic Parsing Plans![/green]")

if __name__ == "__main__":
    initialize_rag_database()