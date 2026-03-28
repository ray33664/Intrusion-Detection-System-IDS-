import tkinter as tk
from tkinter import scrolledtext
import threading
import time
import random
import sqlite3

# -----------------------------
# DATABASE
# -----------------------------
conn = sqlite3.connect("ids_logs.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    time TEXT,
    type TEXT,
    ip TEXT
)
""")
conn.commit()

# -----------------------------
# VARIABLES
# -----------------------------
ip_counter = {}
port_scan = {}

total_packets = 0
alerts = 0

# -----------------------------
# LOG FUNCTION
# -----------------------------
def log_db(alert_type, ip):
    cursor.execute(
        "INSERT INTO logs VALUES (?, ?, ?)",
        (time.ctime(), alert_type, ip)
    )
    conn.commit()

# -----------------------------
# ALERT FUNCTION
# -----------------------------
def show_alert(msg, alert_type, ip):
    global alerts

    alerts += 1

    output.insert(tk.END, msg + "\n")
    output.see(tk.END)

    log_db(alert_type, ip)

    with open("ids_log.txt", "a") as f:
        f.write(msg + "\n")

    update_stats()

# -----------------------------
# SIMULATED TRAFFIC
# -----------------------------
def simulate_traffic():
    global total_packets

    while True:

        time.sleep(1)

        ip = f"192.168.1.{random.randint(1,50)}"
        port = random.randint(20,100)

        total_packets += 1

        # Count requests per IP
        ip_counter[ip] = ip_counter.get(ip, 0) + 1

        # Track ports for scan detection
        if ip not in port_scan:
            port_scan[ip] = set()

        port_scan[ip].add(port)

        # DoS detection
        if ip_counter[ip] > 10:
            msg = f"[ALERT] DoS Attack from {ip}"
            show_alert(msg, "DoS", ip)
            ip_counter[ip] = 0

        # Port scan detection
        if len(port_scan[ip]) > 8:
            msg = f"[ALERT] Port Scan from {ip}"
            show_alert(msg, "Port Scan", ip)
            port_scan[ip].clear()

        update_stats()

# -----------------------------
# STATS
# -----------------------------
def update_stats():
    stats_label.config(
        text=f"Packets: {total_packets}   Alerts: {alerts}"
    )

# -----------------------------
# START IDS
# -----------------------------
def start_ids():
    output.insert(tk.END, "Starting IDS (Simulation Mode)...\n")
    simulate_traffic()

def run_ids():
    thread = threading.Thread(target=start_ids)
    thread.daemon = True
    thread.start()

# -----------------------------
# GUI
# -----------------------------
window = tk.Tk()
window.title("IDS Dashboard (No Libpcap)")
window.geometry("800x600")
window.configure(bg="black")

title = tk.Label(
    window,
    text="INTRUSION DETECTION SYSTEM (SIMULATION)",
    bg="black",
    fg="#00ff00",
    font=("Arial", 16, "bold")
)
title.pack(pady=10)

start_btn = tk.Button(
    window,
    text="Start Monitoring",
    bg="#00ff00",
    fg="black",
    font=("Arial", 12, "bold"),
    command=run_ids
)
start_btn.pack(pady=10)

stats_label = tk.Label(
    window,
    text="Packets: 0   Alerts: 0",
    bg="black",
    fg="#00ff00",
    font=("Arial", 12)
)
stats_label.pack()

output = scrolledtext.ScrolledText(
    window,
    width=95,
    height=25,
    bg="black",
    fg="#00ff00",
    font=("Consolas", 10)
)
output.pack(pady=10)

window.mainloop()