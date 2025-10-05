import re
import csv

from rich.console import Console
from rich.table import Table

console = Console()

pattern = re.compile(
    r'(?P<date>\w{3}\s+\d+\s[\d:]+).*Failed password for (?P<user>\w+) from (?P<ip>[\d.]+)'
)
print(type(pattern))
print(dir(pattern))

# Leer auth.log
# log_file = "/var/log/auth.log"
log_file = "test_auth.log"
out_file_log = "/home/usuario/scripts_logs/fallos_login.csv"
entries = []

try:
    with open(log_file, "r") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                entries.append(match.groupdict())
except FileNotFoundError:
    print(f"Error: no se encontro {log_file}")

# Mostrar en tabla
table = Table(title="Intentos Fallidos de Login")
table.add_column("Fecha", style="cyan")
table.add_column("Usuario", style="magenta")
table.add_column("IP", style="green")

for e in entries:
    table.add_row(e["date"], e["user"], e["ip"])

console.print(table)

# Guardar en CSV
try:
    with open(out_file_log, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["date", "user", "ip"])
        writer.writeheader()
        writer.writerows(entries)
except FileNotFoundError:
    print(f"Error: no se encontro {out_file_log}")