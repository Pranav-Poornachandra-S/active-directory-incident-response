# Active Directory Incident Response Lab

[![Active Directory](https://img.shields.io/badge/Identity-Active_Directory-0078D6?style=for-the-badge&logo=windows11&logoColor=white)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-domain-services)
[![Splunk Enterprise](https://img.shields.io/badge/SIEM-Splunk_Enterprise-000000?style=for-the-badge&logo=splunk&logoColor=white)](https://www.splunk.com/)
[![Sysmon](https://img.shields.io/badge/Telemetry-Sysmon-0080FF?style=for-the-badge&logo=shield&logoColor=white)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![Atomic Red Team](https://img.shields.io/badge/Adversary_Emulation-Atomic_Red_Team-D22128?style=for-the-badge&logo=terminal&logoColor=white)](https://atomicredteam.io/)
[![Kali Linux](https://img.shields.io/badge/Attacker-Kali_Linux-557C93?style=for-the-badge&logo=kalilinux&logoColor=white)](https://www.kali.org/)

An end-to-end Active Directory lab built to simulate real-world adversary TTPs, capture telemetry via Sysmon and Windows Event Logs and perform threat hunting using Splunk Enterprise.

---

## Network & Lab Architecture

The lab consists of an isolated Active Directory domain (`adir.local`) mapped across a `192.168.10.0/24` subnet. Centralized log aggregation is handled by Splunk Universal Forwarders shipping event telemetry directly to a dedicated Splunk Enterprise indexer.

<p align="center">
  <img src="resources/active_directory_incident_response_architecture.jpg" alt="Network Architecture" width="700">
  <br>
</p>

### Subnet & VM Configurations
| Host Role | OS / Software Stack | IP Address | Configured Telemetry |
| :--- | :--- | :--- | :--- |
| **Domain Controller** | Windows Server 2022 (AD DS, DNS) | `192.168.10.7` | Sysmon + Splunk Universal Forwarder |
| **Splunk Server** | Ubuntu Server 22.04 (Splunk Enterprise) | `192.168.10.3` | Centralized Indexer (`index=endpoint`) |
| **Target Workstation** | Windows 10 Pro | `192.168.10.100` | Sysmon + Splunk Universal Forwarder + Atomic Red Team |
| **Attacker Machine** | Kali Linux | `192.168.10.250` | Crowbar |

---

## Environment Provisioning & Domain Setup

### 1. Domain Infrastructure & User Onboarding
Promoted Windows Server to primary Domain Controller for `adir.local` and joined the target Windows 10 workstation (`Target-DESKTOP-2SC49VO`).

| Domain Controller Setup | User Domain Join Verification |
| :---: | :---: |
| ![DC Setup](resources/dc_installation.png) | ![Domain Join](resources/adir_domain_join.png) |

### 2. Active Directory Organizational Structure
Configured standard enterprise Organizational Units (`IT`, `HR`) and populated user accounts.

<p align="center">
  <img src="resources/active_directory_ous.png" alt="AD OUs" width="700">
  <br>
</p>

---

## Adversary Emulation

### 1. RDP Brute-Force
Simulated unauthenticated external access attacks targeting domain user accounts (`jsmith`, `tsmith`) over Remote Desktop Protocol (Port 3389) using `Crowbar` on Kali Linux.

![Crowbar Attack](resources/attack_simulation_kali.png)

### 2. Automated Account Creation
Executed MITRE ATT&CK **T1136.001 (Persistence: Local Account Creation)** using `Invoke-AtomicTest` inside PowerShell to simulate administrative privilege abuse.

![Atomic Red Team Execution](resources/attack_simulation_atomicredteam.png)

---

## Threat Hunting & Telemetry Analysis

### Hunt 1: RDP Brute-Force Detection
* **Objective:** Detect failed login attempts indicative of brute-force.
* **SPL Query:** ```spl
                  index="endpoint" EventCode=4625
                  ```

![Splunk Log Brute Force](resources/splunk_log_failed_login.png)

### Hunt 2: Local Account Creation Detection
* **Objective:** Detect local account creation indicative of persistence.
* **SPL Query:** ```spl
                  index="endpoint" NewLocalUser
                  ```

![Splunk Logs Local Account Creation](resources/splunk_logs_local_account_creation.png)

---
