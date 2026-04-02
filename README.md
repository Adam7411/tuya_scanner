TinyTuya Scanner (Home Assistant Add-on)
TinyTuya Scanner is a Home Assistant add-on that provides a friendly web UI for discovering and organizing Tuya devices on your local network, then enriching them with cloud metadata and local keys.

It is designed as a practical workflow for Tuya setup in HA:

Scan LAN for Tuya devices (IP, Device ID, protocol version, MAC when available).
Fetch cloud keys via Tuya API wizard flow (device names, Local Keys, product data).
Merge results into one operational table for diagnostics and automation prep.
What the add-on provides
Local Tuya device discovery (UDP/TCP scan).
Optional forced subnet scan (CIDR) for harder network cases.
Cloud-key retrieval flow (Tuya project credentials).
Unified device table with:
Name
IP
MAC
Version
Device ID
Product ID
Local Key
Status (online, offline, cloud-only)
Data quality summary:
Online count
Devices with Local Key
Devices with MAC
Devices with Product ID
Per-device DPS diagnostics (raw payload view).
Quick copy/export utilities for integration work.
Credits / Upstream
This add-on is a UI wrapper around the TinyTuya ecosystem and does not replace TinyTuya itself.
Core scanning, protocol handling, and key/cloud workflows are based on the upstream project by jasonacox:

Upstream repository: jasonacox/tinytuya
Please review and support the original repository for protocol updates, device compatibility, and core library improvements.
<img width="1920" height="3873" alt="screenshot_2-04-2026_14-53-02" src="https://github.com/user-attachments/assets/5e9bc87a-7df4-46cf-a37c-7fdcbf387ffa" />
