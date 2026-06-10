# P4-DL — Intrusion Detection System with Deep Learning and P4 Programmable Switches

A network intrusion detection system (IDS) that combines **P4 programmable switches** with **deep learning models** (CNN, GRU, LSTM) to identify and block malicious traffic in real time.

## How It Works

```
Network traffic
      │
      ▼
┌─────────────┐    digest (gRPC/P4Runtime)    ┌──────────────────────┐
│  P4 Switch  │ ─────────────────────────────► │  Control Plane (Py)  │
│ my_switch.p4│                                │  OpenVINO Inference  │
└─────────────┘ ◄───────────────────────────── └──────────────────────┘
                     drop rule insertion
```

1. The P4 switch parses each packet and extracts header fields.
2. It sends a **digest** (compact summary) to the control plane via gRPC.
3. The control plane feeds the features into a CNN, GRU, or LSTM model (running on **OpenVINO**).
4. If an attack is detected, a **drop rule** is dynamically inserted into the switch table.

## Detected Attack Types

| Label | Description |
|---|---|
| Normal | Legitimate traffic |
| MITM | Man-in-the-Middle |
| Uploading | Malicious file upload |
| Ransomware | Ransomware communication |
| SQL_injection | SQL Injection |
| DDoS_UDP | UDP flood |
| DDoS_ICMP | ICMP flood |
| DDoS_TCP | TCP SYN flood |
| DDoS_HTTP | HTTP flood |
| Password | Brute-force / credential attacks |
| Port_Scanning | Port enumeration |
| Vulnerability_scanner | Automated scanner (e.g., Nessus) |
| Backdoor | Remote access backdoor |
| XSS | Cross-Site Scripting exfiltration |
| Fingerprinting | OS/service fingerprinting |

## Supported Protocols

The switch parses and generates digests for the following protocols:

| Protocol | Port | Digest |
|---|---|---|
| ICMP | — | digest1 |
| TCP (generic) | — | digest2 |
| HTTP | 80 | digest3 |
| MQTT | 1883 | digest4/mqttCO |
| ModbusTCP | 501 | digest5 |
| UDP (generic) | — | digest6 |
| DNS | 53 | digest7 |
| ARP | — | digest8 |

## Repository Structure

```
P4-DL/
├── switch/
│   ├── my_switch.p4          # P4_16 dataplane program
│   ├── my_switch.p4i         # Preprocessed P4 (compiler output)
│   └── my_switch.json        # BMv2 behavioral model config
├── controller/
│   └── control.py            # Python control plane (gRPC + ML inference)
└── models/
    ├── cnn_modelo/           # TensorFlow SavedModel — CNN
    ├── gru_model/            # TensorFlow SavedModel — GRU
    ├── lstm_model/           # TensorFlow SavedModel — LSTM
    └── converted_models/     # OpenVINO IR format (.xml + .bin)
        ├── cnn_convert/
        ├── gru_convert/
        └── lstm_convert/
```

## Dataset

The models were trained on the **[Edge-IIoTset](https://ieee-dataport.org/documents/edge-iiotset-new-comprehensive-realistic-cyber-security-dataset-iot-and-iiot-applications)** dataset ([IEEE Xplore paper](https://ieeexplore.ieee.org/document/9751703/)), a comprehensive IoT/IIoT cybersecurity dataset covering 14 attack types across 5 threat categories (DoS/DDoS, Information Gathering, MITM, Injection, Malware).

## Requirements

- Python 3.8+
- [BMv2 `simple_switch_grpc`](https://github.com/p4lang/behavioral-model/blob/main/targets/simple_switch_grpc/README.md) — P4 software switch with gRPC support
- [p4c](https://github.com/p4lang/p4c) — P4 compiler
- Python packages:

```
grpcio
protobuf
p4runtime
openvino-runtime
tensorflow
pandas
numpy
scikit-learn
joblib
```

Install with:

```bash
pip install grpcio protobuf p4runtime openvino-runtime tensorflow pandas numpy scikit-learn joblib
```

## Running

### 1. Compile and start the switch

```bash
# Compile the P4 program (if needed)
p4c --target bmv2 --arch v1model switch/my_switch.p4

# Start BMv2 simple_switch_grpc
simple_switch_grpc \
  --device-id 1 \
  --log-console \
  -i 0@eth0 -i 1@eth1 \
  switch/my_switch.json \
  -- --grpc-server-addr 0.0.0.0:50051
```

### 2. Run the control plane

```bash
cd controller
P4INFO=my_switch.p4info.txt P4BIN=../switch/my_switch.json python control.py
```

The controller connects to `localhost:50051`, subscribes to all digest types, and starts classifying traffic.

## Feature Set

The classifier uses **34+ features** extracted from packet headers:

`src_addr`, `dst_addr`, `srcport`, `dstport`, `udp.stream`, `udp.time_delta`, `dns.qry.type`, `dns.qry.name`, `icmp.checksum`, `icmp.seq_le`, `icmp.unused`, `tcp.ack_raw`, `tcp.checksum`, `tcp.seq`, `tcp.flags`, `tcp.len`, `tcp.ack`, `http.content.length`, `http.request.method`, `http.referer`, `http_request_version`, `http.response`, `http.tls.port`, `mqtt.conack.flags`, `mqtt.conflag.cleansess`, `mqtt.conflags`, `mqtt.hdrflags`, `mqtt.len`, `mqtt.msg_decoded_as`, `mqtt.msgtype`, `mqtt.proto_len`, `mbtcp.len`, `mbtcp.trans_id`, `mbtcp.unit_id`, `arp_opcode`, `arp_hw_size`
