# 🔐  Bluetooth-Tether Proof  –  PowerShell Checker

A single PowerShell script that answers one very specific question—**reliably and deterministically**:

> *“Is this Windows machine’s active Bluetooth-tethered (PAN) connection coming  
> from **the one iPhone I trust**?”*

It does **not** rely on flaky WMI classes, registry tricks, or guessing from gateway MACs.  
Instead it pivots on Windows’ Plug-and-Play **Container ID**: every physical phone and its child interfaces (PAN, audio, HID …) share one GUID.  
The script finds the Bluetooth device in that same container, extracts its **public BD ADDR**, and compares it to the address you store in a tiny JSON file.

| File | Purpose |
|------|---------|
| `tethered_phone_check.ps1` | the checker script |
| `tethered_phone_info.json` | your phone’s friendly name and BD ADDR |

---

## ✨ Why this even matters

1. **Verifiable geo-fence** – Gate secrets on “laptop is physically within a few meters of my phone.”  
2. **Zero install on the phone** – Works with stock iOS / Android tethering.  
3. **Deterministic** – No RSSI thresholds, no timer races.  
4. **Composable** – Returns exit codes, so you can chain it in batch files, Scheduled Tasks, native-messaging hosts, TPM attestation, etc.

---

## ⚙️  Prerequisites

* Windows 10/11 (PowerShell 5.1) **or** PowerShell 7+
* A phone that shares Internet over Bluetooth PAN (iPhone ≈ Personal Hotspot)
* Administrator rights **not** required

---

## 🚀 Quick Start

1. Clone / copy both files into one directory.

2. Edit `tethered_phone_info.json`:

   ```jsonc
   {
     "name"       : "VK's iPhone",
     "mac_address": "D8:DE:3A:B9:E0:EF"   // <— phone’s Bluetooth address
   }

