# TinyTuya Scanner (Home Assistant Add-on)

TinyTuya Scanner is a Home Assistant add-on that provides a clean web UI for discovering Tuya devices on your local network and enriching them with Tuya Cloud metadata (including Local Keys) in one practical workflow.

This project is a **UI wrapper** for the TinyTuya ecosystem.  
It does **not** replace TinyTuya core functionality.

---

## What This Add-on Does

The add-on is designed around a 3-step operational flow:

1. **Scan local network** for Tuya devices (IP, Device ID, protocol version, MAC when available)
2. **Fetch cloud metadata and keys** through Tuya API credentials
3. **Merge everything into one table** for diagnostics and automation preparation

---

## Features

- Local Tuya device discovery (UDP/TCP scan)
- Optional **forced subnet scan (CIDR)** for harder network layouts
- Tuya Cloud key retrieval flow (Access ID / Secret)
- Unified device table with:
  - Name
  - IP
  - MAC
  - Version
  - Device ID
  - Product ID
  - Local Key
  - Status (`online`, `offline`, `cloud-only`)
- Data quality summary:
  - Online count
  - Devices with Local Key
  - Devices with MAC
  - Devices with Product ID
- Per-device DPS diagnostics (raw JSON payload view)
- Copy/export helpers for integration and debugging
- Multi-language UI (EN / PL / DE / FR)

---

## Installation

### 1) Add this repository to Home Assistant

1. Open Home Assistant
2. Go to **Settings -> Add-ons -> Add-on Store**
3. Click the menu icon (top-right, three dots) -> **Repositories**
4. Add your repository URL:

```text
https://github.com/Adam7411/tuya_scanner
```

### 2) Install the add-on

1. Find **TinyTuya Scanner** in the Add-on Store
2. Click **Install**
3. Start the add-on
4. Open the Web UI

---

## Tuya API Setup (for key retrieval)

To fetch Local Keys and cloud metadata:

1. Log in to [iot.tuya.com](https://iot.tuya.com)
2. Create a Cloud project or open an existing one  
   (`Project Management -> Open Project`)
3. In **Overview**, copy:
   - `Access ID` / `Client ID`
   - `Access Secret` / `Client Secret`
4. In the add-on UI, run the cloud-key retrieval step and provide your project credentials

Helpful screenshot from the add-on UI:

![Tuya API setup help](www/tuya.png)

---

## Recommended Workflow

1. Run **Network Scan**
2. Run **Cloud Key Retrieval**
3. Review the merged table:
   - Confirm `Local Key` availability
   - Check device status (`online/offline/cloud-only`)
   - Use DPS diagnostics for integration troubleshooting

---

## Troubleshooting

- **No devices found in local scan**
  - Try forced CIDR scan (for example `192.168.100.0/24`)
  - Ensure devices and HA are on reachable network segments

- **Missing Local Keys**
  - Verify Access ID/Secret
  - Confirm the same Tuya account/project owns the devices
  - Re-run cloud retrieval after confirming project authorization

- **Device appears as cloud-only**
  - Device is known in cloud but not reachable locally
  - Check Wi-Fi/VLAN isolation, subnet routing, and firewall rules

- **DPS call fails**
  - Device may be offline, sleeping, or incompatible with direct local status polling at that moment

---

## Credits / Upstream

This add-on builds on the TinyTuya ecosystem by **jasonacox**:

- Upstream project: [jasonacox/tinytuya](https://github.com/jasonacox/tinytuya)

Please support the upstream repository for protocol updates, compatibility improvements, and core library progress.

---

## Disclaimer

This add-on provides a Home Assistant-friendly interface and workflow around TinyTuya mechanisms.  
Scanning, protocol behavior, and cloud/key logic originate from TinyTuya and Tuya platform behavior.
