import os
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

    # --- ENRICHED KNOWLEDGE BASE ---
    examples = [
        {
            "id": "net_iptables_1",
            "category": "NETWORK",
            "log": "Jan 16 06:25:14 inet-firewall kernel: [123.456] dmz-fw DROP IN=eth0 OUT= MAC=... SRC=192.168.1.50 DST=10.0.0.5 PROTO=TCP",
            "regex": r"(?i).*?src=(?P<src_ip>\d+\.\d+\.\d+\.\d+).*?dst=(?P<dst_ip>\d+\.\d+\.\d+\.\d+).*?proto=(?P<proto>\S+).*?(?P<action>DROP|ACCEPT|REJECT|DENY|BLOCK|ALLOW)",
            "mappings": '{"src_ip": "src_ip", "dst_ip": "dst_ip", "proto": "proto", "action": "action"}'
        },
        {
            "id": "auth_pam_unix_1",
            "category": "AUTHENTICATION",
            "log": "Jan 16 06:25:14 intranet-server CRON[14139]: pam_unix(cron:session): session closed for user root",
            "regex": r"(?i).*?(?P<action>session|login|password).*?(?P<status>opened|closed|failed|success).*?(?:user|for)\s+(?P<user>\S+)",
            "mappings": '{"user": "user", "action": "action", "status": "status"}'
        },
        {
            "id": "web_apache_1",
            "category": "WEB",
            "log": "192.168.1.100 - - [16/Jan/2026:06:25:14 +0000] \"GET /index.html HTTP/1.1\" 200 1024",
            "regex": r"(?i)^(?P<src_ip>\d+\.\d+\.\d+\.\d+).*?(?P<method>GET|POST|PUT|DELETE)\s+(?P<url>\S+)\s+HTTP.*?\"?\s+(?P<status>\d{3})",
            "mappings": '{"src_ip": "src_ip", "method": "method", "url": "url", "status": "status"}'
        },
        {
            "id": "web_nginx_proxy_1",
            "category": "WEB",
            "log": "cloud.dmz.smith.santos.com:443 172.21.129.224 - - [16/Jan/2022:11:34:40 +0000] \"GET /apps/files HTTP/1.1\" 200 681",
            "regex": r"(?i)^(?:[a-z0-9.-]+:\d+\s+)?(?P<src_ip>\d+\.\d+\.\d+\.\d+).*?(?P<method>GET|POST|PUT|DELETE)\s+(?P<url>\S+)\s+HTTP.*?\"?\s+(?P<status>\d{3})",
            "mappings": '{"src_ip": "src_ip", "method": "method", "url": "url", "status": "status"}'
        },
        {
            "id": "auth_dovecot_imap_1",
            "category": "AUTHENTICATION",
            "log": "Jan 13 16:45:13 hayes-mail dovecot: imap(norman.humphries): Logged out in=112 out=666",
            "regex": r"(?i).*?(?:imap|pop3)\((?P<user>[^)]+)\):\s+(?P<action>Logged out|Login).*?(?:rip=(?P<src_ip>\d+\.\d+\.\d+\.\d+))?",
            "mappings": '{"user": "user", "action": "action", "status": "action"}'
        },
        {
            "id": "auth_sudo_1",
            "category": "AUTHENTICATION",
            "log": "Jan 13 12:03:40 rogersturnbull-mail sudo:      ait : TTY=pts/0 ; PWD=/home/ait ; USER=root ; COMMAND=/bin/sh",
            "regex": r"(?i).*?sudo:\s+(?P<user>\S+)\s*:.*?USER=(?P<target_user>\S+).*?COMMAND=(?P<action>.*)",
            "mappings": '{"user": "user", "action": "action", "status": "action"}'
        }
    ]

    collection.add(
        ids=[ex["id"] for ex in examples],
        documents=[ex["log"] for ex in examples],
        metadatas=[{"category": ex["category"], "regex": ex["regex"], "mappings": ex["mappings"]} for ex in examples]
    )
    
    rprint("[green]✓ Offline RAG Database enriched with complex schemas![/green]")

if __name__ == "__main__":
    initialize_rag_database()