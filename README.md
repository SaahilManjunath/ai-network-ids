# 🛡️ AI-Driven Network Telemetry & Intrusion Detection System

An autonomous, machine-learning-powered Intrusion Detection System (IDS) that monitors live network traffic and detects anomalous packet behavior in real-time. 

Built as a lightweight alternative to signature-based detection, this tool utilizes an **Isolation Forest** algorithmic model to identify zero-day network anomalies based on packet telemetry rather than static threat feeds.

## ⚙️ Core Technology Stack
* **Language:** Python 3.10+
* **Machine Learning:** Scikit-learn, NumPy, Pandas (Isolation Forest)
* **Network Telemetry:** Scapy (Packet sniffing, protocol extraction)

## 🚀 Features
- **Real-Time Packet Sniffing:** Captures live TCP/UDP traffic traversing the network interface.
- **Unsupervised Anomaly Detection:** Employs an Isolation Forest model trained on baseline metrics to flag statistical outliers.
- **Telemetry Extraction:** Analyzes critical packet features including payload size, Time-to-Live (TTL), and protocol configurations.
- **Automated Alerting:** Generates immediate terminal warnings for suspicious infrastructure connections.

## 🛠️ Installation & Usage

1. **Clone the repository:**
   ```bash
   > git clone https://github.com/SaahilManjunath/ai-network-ids.git
   > cd ai-network-ids
   > pip install -r requirements.txt
   > sudo python3 ids_engine.py
