import os
import time
import requests
from rich import print

INGEST_URL = "http://localhost:8000/api/v1/ingest"

def process_file(file_path, batch_size, delay_seconds, total_sent):
    batch = []
    print(f"\n[bold magenta]► Opening log file:[/bold magenta] {os.path.basename(file_path)}")
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                batch.append(line)
                
                if len(batch) >= batch_size:
                    payload = {"payloads": batch, "transport": "http_api"}
                    try:
                        response = requests.post(INGEST_URL, json=payload, timeout=60)
                        if response.status_code == 201:
                            total_sent += len(batch)
                            print(f"[green]✓ Pushed batch of {len(batch)} logs[/green] (Total: {total_sent})")
                        else:
                            print(f"[red]⚠ API Error: {response.status_code}[/red]")
                    except requests.exceptions.Timeout:
                        print("[yellow]⚠ API Timeout: Backend is processing AI...[/yellow]")
                    except requests.exceptions.RequestException:
                        print(f"[bold red]✗ Connection error. Retrying in 5s...[/bold red]")
                        time.sleep(5)
                    
                    batch = []
                    time.sleep(delay_seconds)
                    
        # Flush the remaining logs at the end of the file
        if batch:
            payload = {"payloads": batch, "transport": "http_api"}
            try:
                response = requests.post(INGEST_URL, json=payload, timeout=60)
                if response.status_code == 201:
                    total_sent += len(batch)
                    print(f"[green]✓ Pushed final batch of {len(batch)} logs[/green] (Total: {total_sent})")
            except Exception:
                print(f"[yellow]⚠ Failed to push final batch.[/yellow]")
                    
    except Exception as e:
        print(f"[red]Error reading {file_path}: {e}[/red]")
    return total_sent

def stream_logs(target_path, batch_size=2, delay_seconds=4.0):
    print(f"\n[bold cyan]🚀 Initializing Universal ULPF Log Pump...[/bold cyan]")
    total_sent = 0
    found_valid_file = False

    # If it's a direct file, process it immediately
    if os.path.isfile(target_path):
        if os.path.getsize(target_path) == 0:
            print(f"[yellow]⚠ Skipping {os.path.basename(target_path)} (File is exactly 0 bytes)[/yellow]")
            return
        process_file(target_path, batch_size, delay_seconds, total_sent)
        return

    # If it's a directory, walk through it and filter out junk
    for root, _, files in os.walk(target_path):
        for file in files:
            file_lower = file.lower()

            if 'error' in file_lower:
                continue

            valid_substrings = ['auth', 'syslog', 'kern', 'access', 'chaos']
            if not any(sub in file_lower for sub in valid_substrings):
                continue

            file_path = os.path.join(root, file)
            if os.path.getsize(file_path) == 0:
                print(f"[yellow]⚠ Skipping {file} (File is exactly 0 bytes)[/yellow]")
                continue

            found_valid_file = True
            total_sent = process_file(file_path, batch_size, delay_seconds, total_sent)
            
    if not found_valid_file and not os.path.isfile(target_path):
        print(f"[yellow]⚠ No valid, non-empty log files found in directory.[/yellow]")

if __name__ == "__main__":
    print("[bold cyan]=== ULPF Log Pump ===[/bold cyan]")
    while True:
        raw_input = input("Paste the full path to a log folder OR a specific log file: ")
        clean_path = raw_input.strip().strip('"').strip("'")
        
        if os.path.exists(clean_path):
            stream_logs(clean_path, batch_size=2, delay_seconds=4.0)
            break
        else:
            print(f"[bold red]Path not found:[/bold red] {clean_path}\nPlease try again.\n")