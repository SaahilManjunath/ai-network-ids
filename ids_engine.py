import logging
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
import warnings

# Suppress sklearn warnings for clean terminal output
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [AI-IDS] - %(message)s')

class NetworkIDS:
    def __init__(self):
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.trained = False
        
    def train_baseline_model(self):
        logging.info("Training ML model on baseline network telemetry...")
        # Synthetic baseline data: [Packet Size, Protocol (6=TCP, 17=UDP), TTL]
        normal_traffic = np.array([
            [64, 6, 64], [128, 6, 64], [256, 17, 128], 
            [512, 6, 64], [64, 17, 128], [1024, 6, 64]
        ] * 100)
        
        self.model.fit(normal_traffic)
        self.trained = True
        logging.info("Model training complete. Listening for anomalies...")

    def analyze_packet(self, packet):
        if not self.trained:
            return

        if IP in packet:
            # Extract telemetry features
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            pkt_size = len(packet)
            ttl = packet[IP].ttl
            
            protocol = 0
            if TCP in packet:
                protocol = 6
            elif UDP in packet:
                protocol = 17

            # Prepare feature array for prediction
            features = np.array([[pkt_size, protocol, ttl]])
            
            # Predict: 1 is normal, -1 is anomaly
            prediction = self.model.predict(features)
            
            if prediction[0] == -1:
                logging.warning(f"🚨 ANOMALY DETECTED | Src: {src_ip} -> Dst: {dst_ip} | Size: {pkt_size}B | Proto: {protocol} | TTL: {ttl}")

def start_ids():
    ids = NetworkIDS()
    ids.train_baseline_model()
    
    # Sniff network traffic, passing each packet to the ML engine
    try:
        sniff(prn=ids.analyze_packet, store=False)
    except PermissionError:
        logging.error("Permission denied: Please run this script with sudo/administrator privileges.")

if __name__ == "__main__":
    start_ids()
