HomeGuard aims to sit in the gap between those two: real detection, explained simply.
Here is a link to our wiki! : https://github.com/Etown-CS/26-27_HomeGuard/wiki

# HomeGuard

A lightweight intrusion detection system that watches traffic on your home or small-office network and flags suspicious device behavior without needing you to be a security expert. HomeGuard captures network traffic using Scapy/pyshark, extracts flow-level features per device, and runs an anomaly detection model (Isolation Forest or a small autoencoder) to catch behavior that doesn't fit a device's normal pattern.
Example: if your smart camera suddenly starts beaconing out to an unfamiliar IP address, HomeGuard notices.

Most alerts from security tools are cryptic logs meant for analysts. HomeGuard translates detections into plain language. No raw packet dumps, just a clear heads-up and enough context to decide what to do next.

## External Requirements

For the Sniffer.py, it needs to run on a Linux CLI:
- ```pip install scapy```
If pip is not installed on your Linux server, run: ```sudo apt update && sudo apt install python3-pip -y```

- python3 sniffer.py --list-ifaces
- sudo python3 sniffer.py -i (interface) -c 50 -o capture.csv

**Python dependencies:**
```bash
```bash
pip install scapy pandas scikit-learn==1.8.0 ollama
```
The saved model was trained with scikit-learn 1.8.0, so use that version to avoid load warnings.

**Ollama (runs the language model locally):**
- Download and install Ollama from ollama.com and make sure it is running.
- Pull a model:
```bash
ollama pull dr-ry/foundation-sec-8b-instruct-chat-GGUF   # Foundation-Sec-8B-Instruct, about 4.9 GB
ollama pull llama3.2:3b                                  # Llama 3.2 3B, about 2 GB
```
Choose the active model by editing the `MODEL` line near the top of `backend/llm_explain.py`.

Note: do not pull `FenkoHQ/Foundation-Sec-8B:latest`. It is a 16 GB unquantized base model that will not fit on most laptops.

## Setup

The setup for the sniffer would just need to be ran before loading on the website locally.

## Overall Setup

1. Clone the repository and navigate to the project folder
2. Install all Python dependencies listed above
3. Install Ollama and pull the Llama 3.2 3B model
4. Make sure Ollama is running before executing the LLM script

## Running

**Step 1 — Capture live network traffic (Linux only, requires sudo):**
```bash
sudo python sniffer.py -i (interface) -c 50 -o capture.csv
```

**Step 2 — Score traffic and flag anomalies:**
```bash
python score_flows.py
```
Output: `scored_flows.csv` and `flagged_events.csv`

**Step 3 — Generate plain-language explanations (Ollama must be running):**
```bash
python llm_explain.py
```
Output: `alerts.json`

**Step 4 — View the dashboard:**
```bash
python -m http.server 8000
```
Then open your browser and go to `http://localhost:8000`

# Deployment

We aim to hopefully be able to deploy this to the real world. We are working on also making sure the website runs smoothly on other devices so the transition when deployed would be much easier.

# Authors

Farnaz (Teddy) Bazyar - bazyarf@etown.edu
Isabella La Face - lafacei@etown.edu
Kylie Ueda - uedak@etown.edu
