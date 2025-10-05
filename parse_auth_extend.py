#!/usr/bin/env python3
# ~/scripts_logs/parse_auth_improved.py
import re
import csv
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

# ---------- PATTERNS ----------
pattern_sshd = re.compile(
    r'(?P<date>\w{3}\s+\d+\s[\d:]+)\s+'            
    r'(?P<host>\S+)\s+'                            
    r'sshd\[\d+\]:\s+'
    r'Failed password for (?:invalid user\s+)?'   
    r'(?P<user>\S+) from (?P<ip>[0-9a-fA-F:\.]+)', 
    re.IGNORECASE
)

pattern_sudo_pam = re.compile(
    r'(?P<date>\w{3}\s+\d+\s[\d:]+)\s+'
    r'(?P<host>\S+)\s+sudo:\s+pam_unix\([^\)]+\):\s+authentication failure;.*user=(?P<user>\S+)',
    re.IGNORECASE
)

pattern_sudo_summary = re.compile(
    r'(?P<date>\w{3}\s+\d+\s[\d:]+)\s+'
    r'(?P<host>\S+)\s+sudo:\s+'
    r'(?P<user>\S+)\s*:\s*(?P<count>\d+)\s+incorrect password attempts',
    re.IGNORECASE
)

def parse_file(path: Path):
    text = path.read_text(encoding="utf-8", errors="ignore")
    entries = []

    for m in pattern_sshd.finditer(text):
        entries.append({
            "type": "sshd_failed",
            "date": m.group("date"),
            "host": m.group("host"),
            "user": m.group("user"),
            "ip": m.group("ip"),
            "extra": ""
        })

    for m in pattern_sudo_pam.finditer(text):
        entries.append({
            "type": "sudo_pam_failure",
            "date": m.group("date"),
            "host": m.group("host"),
            "user": m.group("user"),
            "ip": "",
            "extra": "pam_auth_failure"
        })

    for m in pattern_sudo_summary.finditer(text):
        entries.append({
            "type": "sudo_incorrect_attempts",
            "date": m.group("date"),
            "host": m.group("host"),
            "user": m.group("user"),
            "ip": "",
            "extra": f"count={m.group('count')}"
        })

    entries.sort(key=lambda e: e["date"])
    return entries

def print_table(entries):
    table = Table(title="Eventos de autenticación encontrados")
    table.add_column("Tipo")
    table.add_column("Fecha")
    table.add_column("Host")
    table.add_column("Usuario")
    table.add_column("IP")
    table.add_column("Extra")
    for e in entries:
        table.add_row(e["type"], e["date"], e["host"], e["user"], e["ip"], e["extra"])
    console.print(table)

def save_csv(entries, outpath: Path):
    with outpath.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["type","date","host","user","ip","extra"])
        writer.writeheader()
        writer.writerows(entries)

# ---------- MAIN ----------
def main():
    # a futuro 
    # la idea es que n oeste harcodeada sino que te pregunte que archivo de log queries auditar
    # para poder parsear archivos de log antiguos
    #evalular si lso que estna ocmprimidos desocmprimirlo en el script o por fuera y luego deicrle al 
    #script que archivo abrir 

    log_file = Path("/var/log/auth.log.1") 
    # al crear el csv habria que chequer si el archivo existe y elegir si :
    # actualizar el archivo o crear otro
    
    csv_file = Path.home() / "output_logs" 

    if not log_file.exists():
        console.print(f"[red]Archivo no encontrado:[/red] {log_file}")
        return

    entries = parse_file(log_file)
    print_table(entries)
    save_csv(entries, csv_file)
    console.print(f"[green]Guardado CSV en:[/green] {csv_file}")

if __name__ == "__main__":+
    main()
