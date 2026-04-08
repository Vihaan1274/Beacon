# 📡 BeaconMesh v2.0

### Serverless P2P Tactical Communication Protocol

**BeaconMesh** is a specialized, infrastructure-independent communication tool built for situations where traditional networks (Wi-Fi, cellular, centralized servers) are congested, compromised, or simply unavailable.

Unlike standard chat apps, BeaconMesh uses **manual WebRTC signaling via high-density QR codes** to create direct, encrypted peer-to-peer (P2P) connections—without a single server hop.

---

## 🛠 The Problem: The “Centralized Failure”

Modern communication platforms (WhatsApp, Discord, Telegram) depend on a **signaling server** to introduce devices.  
If that server goes down—or the network backbone gets overloaded during a campus fest or emergency—the app turns into a brick.

---

## 🚀 The Solution: Serverless P2P

BeaconMesh removes the middleman entirely.  
Users act as the signaling layer by exchanging QR codes, forming a direct browser-to-browser tunnel that is:

- **Works Offline**  
  As long as peers are on the same local network (LAN / campus Wi-Fi)

- **Zero Logs**  
  No metadata, IP addresses, or timestamps are ever stored

- **Resilient**  
  Independent of ISP backbone outages

---

## ✨ Key Features

- **Manual Handshake Flow**  
  A tactical 3-step process to connect devices via QR scanning

- **SDP Optimization & Compression**  
  Uses `zlib` (via `pako`) and custom stripping logic to compress bulky WebRTC session descriptions into scannable QR patterns

- **Tactical UI / UX**  
  High-contrast, OLED-friendly dark theme designed for low-light visibility and battery efficiency

- **End-to-End Encryption**  
  Powered by WebRTC’s native DTLS / SCTP encryption

- **Privacy First**  
  No accounts, no cookies, no tracking

---

## 🏗 Technical Stack

- **Frontend:** HTML5, Tailwind CSS  
- **P2P Engine:** Vanilla JavaScript WebRTC API (`RTCPeerConnection`)  
- **Compression:** `pako` (Zlib implementation)  
- **QR Engine:** `qrcode.js`, `html5-qrcode`  
- **Hosting:** Google Firebase Hosting (secure HTTPS context)

---

## 📖 How to Use (The Handshake)

1. **Host a Beacon**  
   User A clicks **Host** and waits for ICE candidates to gather.  
   A QR code appears.

2. **Join a Mesh**  
   User B clicks **Join** and scans User A’s QR code.

3. **Generate Answer**  
   User B’s device generates an **Answer QR code**.

4. **Finalize**  
   User A scans User B’s Answer QR.

5. **Establish Mesh**  
   The secure P2P data channel opens automatically.

---

## 🔧 Local Testing

WebRTC requires a secure context (HTTPS). For local testing:

- **Localhost**  
  Open two tabs on `http://localhost:3000`

- **HTTPS Tunnel**  
  ```bash
  npx localtunnel --port 3000
  ```
  
---

## 🛡 Security Note

BeaconMesh is intended for decentralized coordination. Because it uses no server, it is immune to server-side data breaches. However, it relies on the physical security of the initial QR exchange to prevent Man-in-the-Middle (MITM) attacks.
