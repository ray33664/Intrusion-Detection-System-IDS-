from scapy.all import *
from collections import defaultdict
import threading
import time
import tkinter as tk
from tkinter import scrolledtext
import sqlite3
import smtplib
import matplotlib.pyplot as plt

# -----------------------------
# DATABASE SETUP
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
# GLOBAL VARIABLES
# -----------------------------
ip_counter = defaultdict(int)
port_scan = defaultdict(set)

THRESHOLD = 20
TIME_WINDOW = 10

start_time = time.time()

total_packets = 0
alerts_count = 0
packet_history = []

# -----------------------------
# EMAIL ALERT
# -----------------------------
def send_email(msg):
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login("your_email@gmail.com", "your_app_password")

        message = f"Subject: IDS Alert\n\n{msg}"
        server.sendmail("your_email@gmail.com", "receiver@gmail.com", message)
        server.quit()
    except:
        pass

# -----------------------------
# LOG DATABASE
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
    global alerts_count

    alerts_count += 1

    output.insert(tk.END, msg + "\n")
    output.see(tk.END)

    log_db(alert_type, ip)
    send_email(msg)

    update_stats()

# -----------------------------
# DETECTION ENGINE
# -----------------------------
def detect_attack(packet):
    global total_packets, start_time

    total_packets += 1
    packet_history.append(total_packets)

    update_graph()
    update_stats()

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        ip_counter[src_ip] += 1

        current_time = time.time()

        if current_time - start_time > TIME_WINDOW:
            ip_counter.clear()
            start_time = current_time

        if ip_counter[src_ip] > THRESHOLD:
            msg = f"[ALERT] DoS Attack from {src_ip}"
            show_alert(msg, "DoS", src_ip)

    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        port = packet[TCP].dport

        port_scan[src_ip].add(port)

        if len(port_scan[src_ip]) > 10:
            msg = f"[ALERT] Port Scan from {src_ip}"
            show_alert(msg, "Port Scan", src_ip)

# -----------------------------
# GRAPH
# -----------------------------
def update_graph():
    if len(packet_history) > 50:
        packet_history.pop(0)

    plt.clf()
    plt.plot(packet_history)
    plt.title("Packet Traffic")
    plt.pause(0.01)

# -----------------------------
# STATS
# -----------------------------
def update_stats():
    stats_label.config(
        text=f"Packets: {total_packets}   Alerts: {alerts_count}"
    )

# -----------------------------
# START IDS
# -----------------------------
def start_ids():
    sniff(prn=detect_attack, store=0)

def run_ids():
    thread = threading.Thread(target=start_ids)
    thread.daemon = True
    thread.start()

# -----------------------------
# GUI
# -----------------------------
window = tk.Tk()
window.title("Final Year IDS Dashboard")
window.geometry("900x650")
window.configure(bg="black")

title = tk.Label(
    window,
    text="INTRUSION DETECTION SYSTEM - FINAL PROJECT",
    bg="black",
    fg="#00ff00",
    font=("Arial", 18, "bold")
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
start_btn.pack()

stats_label = tk.Label(
    window,
    text="Packets: 0   Alerts: 0",
    bg="black",
    fg="#00ff00",
    font=("Arial", 12)
)
stats_label.pack(pady=5)

output = scrolledtext.ScrolledText(
    window,
    width=110,
    height=25,
    bg="black",
    fg="#00ff00",
    font=("Consolas", 10)
)
output.pack(pady=10)

plt.ion()  # enable live graph

window.mainloop()