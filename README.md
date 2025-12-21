# Aegis

## Overview
Aegis is a lightweight, hybrid anomaly-based Intrusion Detection System (IDS) designed to detect unusual network traffic patterns. It combines **statistical baselines** and an **Isolation Forest machine learning model** to identify anomalies, including zero-day-style attacks, without relying on signature-based detection.

Key features:
- Anomaly detection based on entropy, packet rates, byte rates, inter-arrival times, and protocol ratios.
- Optional Isolation Forest ML model for detecting subtle and previously unseen attacks.
- Configurable detection mode: hybrid (stats + ML), ML-only, or statistics-only.
- Supports processing of PCAP files for offline analysis.

## Key Components
- `scripts/analyze_pcap.py`: Main script to analyze PCAP files and generate anomaly alerts.
- `scripts/train_if_model.py`: Trains the Isolation Forest ML model on normal traffic.
- `config/default.yaml`: Configure features, window size, ML weights, and baseline statistics.
- `data/raw/`: Folder for raw PCAP files.
- `data/baselines/`: Stores trained ML models and baseline statistics.
- `src/features/`, `src/capture/`, `src/detection/`: Core modules for feature extraction, packet capture, and anomaly scoring.

## Installation
1. Clone the repository:
```bash
git clone https://github.com/ayaannshaikhh/aegis.git
cd aegis
```
2. Create a Python virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # Linux / macOS
venv\Scripts\activate     # Windows
```
3. Install dependencies:
```bash
pip install -r requirements.txt
```
## Usage
### Training the ML Model
Train the Isolation Forest using normal traffic PCAP:
```bash
python -m scripts/train_if_model --pcap data/raw/normal_train.pcap
```
This will generate `data/baselines/isolation_forest.pkl`.

### Running Detection
Analyze a test PCAP using hybrid anomaly detection:
```bash
python -m scripts/analyze_pcap --pcap data/raw/test.pcap
```
- Alerts will be printed to the console for windows flagged as anomalous.
- Behaviour can be adjusted via config/default.yaml (window size, ML weight, stats weight, and features).

### Configuring Detection
- **Hybrid mode:** Combine statistical baseline and ML (ml.weight < 1, stats_weight < 1).
- **ML-only mode:** Set ml.weight: 1.0 and stats_weight: 0.0.
- **Stats-only mode:** Set ml.weight: 0.0 and stats_weight: 1.0.
- `window_seconds` controls the size of sliding windows for feature extraction.

## Datasets
- Supports PCAP files from publicly available sources such as the CTU-13 botnet dataset.
- Training should be performed on normal traffic only.
