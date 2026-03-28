# Intrusion Detection System (IDS) Dashboard

A real-time Intrusion Detection System built using Python that monitors network traffic and detects suspicious activities such as DoS attacks and port scanning.

## Features

- Real-time packet monitoring using Scapy
- Detection of DoS attacks and Port Scans
- GUI dashboard with live alerts
- SQLite database logging
- Text log file generation
- Email alert system
- Live traffic graph visualization

## Technologies Used

- Python
- Scapy
- Tkinter
- SQLite
- Matplotlib

## How to Run

1. Install dependencies:

pip install scapy matplotlib

2. Run the project:

python ids_final.py

## Output

- Live alerts in GUI
- Logs stored in:
  - ids_logs.db (database)
  - ids_log.txt (text file)

## Project Structure



├── ids_final.py
├── ids_logs.db
├── ids_log.txt


## Use Case

This project simulates a real-world Intrusion Detection System used in Security Operations Centers (SOC) to monitor and detect cyber attacks.

## Author

Cybersecurity Student Project
