# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/cmade/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called "lor-shopping-list.txt" on the desktop.These events began at: 2025-06-23T12:00:02.0334036Z


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "cwav3-test-mde"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-06-23T12:00:02.0334036Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1098" alt="image" src="https://github.com/user-attachments/assets/df669f47-45e3-4e66-a8a7-775783bc302a" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string: tor-browser-windows-x86_64-portable-14.5.3.exe. Based on the logs returned on the morning of June 23rd, 2025, precisely at 7:59 AM, a user on the "cwav3-test-mde" machine, identified as "cwav3," initiated an executable file named "tor-browser-windows-x86_64-portable-14.5.3.exe" from their downloads, the digital footprint of which was a unique SHA256 hash.

**Query used to locate event:**

```kql
DeviceProcessEvents  
| where DeviceName == "cwav3-test-mde"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1103" alt="image" src="https://github.com/user-attachments/assets/f03b461f-9e26-4c3c-bb53-5eed4fa1ef6b" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “employee” actually opened the tor browser. There was evidence they did open it at: 2025-06-23T12:00:34.8579639Z.

There were several other instances of firefox.exe (Tor) as well as tor.exe that spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "cwav3-test-mde"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1121" alt="image" src="https://github.com/user-attachments/assets/373e5b87-0722-4edf-bbd8-aecfa1bc0b6e" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known ports. At 2025-06-23T12:01:28.7877572Z.On the morning of June 23rd, 2025, at 8:01 AM, the Tor browser on the "cwav3-test-mde" computer, operated by "cwav3," successfully established a connection to the website https://www.google.com/search?q=pisodes.com at the IP address 192.87.28.28 through port 9001. There were few other connections over port.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "cwav3-test-mde"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
```
<img width="1137" alt="image" src="https://github.com/user-attachments/assets/bfc7c793-88ee-4330-892d-a4d76623b9b4" />


---

# 🕒 Chronological Events - Tor Browser Activity Timeline

## 📥 File Download - Tor Installer
- **Timestamp:** 2025-06-23T07:59:00Z  
- **Event:** User `cwav3` on machine `cwav3-test-mde` downloaded and initiated the Tor installer executable.  
- **Action:** Tor installer execution detected.  
- **File Path:**  
  `C:\Users\cwav3\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

---

## ⚙️ Tor Browser Installer Execution
- **Timestamp:** 2025-06-23T07:59:45Z  
- **Event:** Silent execution of the installer by `cwav3`.  
- **Action:** Tor installer executed (`/S` flag).  
- **File Path:**  
  `C:\Users\cwav3\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

---

## 📁 Tor-related File Creation (Licenses & Executable)
- **Timestamp:** 2025-06-23T08:00:02Z  
- **Event:** Creation of installation-related files.  
- **Action:** Tor installation files created.  
- **File Paths:**  
  - `...Tor-Launcher.txt`  
  - `...Torbutton.txt`  
  - `...tor.txt`  
  - `...tor.exe`  
  *(Full paths truncated for brevity.)*

---

## 🔗 Tor Browser Shortcut Created
- **Timestamp:** 2025-06-23T08:00:12Z  
- **Event:** Desktop shortcut creation.  
- **Action:** Tor Browser shortcut created.  
- **File Path:**  
  `C:\Users\cwav3\Desktop\Tor Browser\Tor Browser.lnk`

---

## 🚀 Tor Browser Process Created (firefox.exe)
- **Timestamp:** 2025-06-23T08:00:34Z  
- **Event:** Main process launched.  
- **Action:** Tor Browser process initiated.  
- **File Path:**  
  `C:\Users\cwav3\Desktop\Tor Browser\Browser\firefox.exe`

---

## 💾 Tor Browser Data File Created
- **Timestamp:** 2025-06-23T08:00:36Z  
- **Event:** Profile data file creation.  
- **Action:** Created `storage.sqlite`.  
- **File Path:**  
  `...profile.default\storage.sqlite`

---

## 🔄 Multiple Tor Browser Processes Initiated
- **Timestamp:** 2025-06-23T08:00:37Z – 08:06:23Z  
- **Event:** Spawn of multiple Tor/Firefox processes.  
- **Action:** Sustained Tor activity observed.  
- **File Paths:**  
  - `...firefox.exe`  
  - `...tor.exe`

---

## 💾 Tor Browser Data File Created
- **Timestamp:** 2025-06-23T08:00:42Z  
- **Event:** New data file added.  
- **Action:** Created `storage-sync-v2.sqlite`.  
- **File Path:**  
  `...profile.default\storage-sync-v2.sqlite`

---

## 🌐 Tor Browser Connection Success
- **Timestamp:** 2025-06-23T08:00:51Z  
- **Event:** Outbound connection to Tor node.  
- **Action:** Tor connection established.  
- **Remote IP:** `114.23.164.80`  
- **Port:** `9001`

---

## 🌐 Tor Connection to `.onion` Gateway
- **Timestamp:** 2025-06-23T08:01:19Z  
- **Event:** Connected to hidden service domain.  
- **Action:** Tor connection established.  
- **Remote IP:** `192.121.108.237`  
- **Remote URL:** `https://www.xpbyntjqh6wvlaglxaji2k.com`

---

## 🌐 Tor Browser Connection to pisodes.com
- **Timestamp:** 2025-06-23T08:01:28Z  
- **Event:** Outbound connection to known domain.  
- **Action:** Tor connection established.  
- **Remote IP:** `192.87.28.28`  
- **Port(s):** `9001`, `443`  
- **Remote URL:** `https://www.pisodes.com`

---

## 📝 Suspicious File Created (tor-shopping-list.txt)
- **Timestamp:** 2025-06-23T08:17:51Z  
- **Event:** Potential sensitive data or note created.  
- **Action:** File creation.  
- **File Path:**  
  `C:\Users\cwav3\Desktop\tor-shopping-list.txt`

---

## 🔗 Suspicious Shortcut Created
- **Timestamp:** 2025-06-23T08:17:52Z  
- **Event:** Shortcut to the above `.txt` created.  
- **Action:** Shortcut file created.  
- **File Path:**  
  `C:\Users\cwav3\AppData\Roaming\Microsoft\Windows\Recent\tor-shopping-list.lnk`

---

## 💾 Tor Data File Created
- **Timestamp:** 2025-06-23T08:19:03Z  
- **Event:** Additional browser storage file created.  
- **Action:** Created `webappsstore.sqlite`.  
- **File Path:**  
  `...profile.default\webappsstore.sqlite`

---

## 👤 User-Reported Tor Installer Download
- **Timestamp:** 2025-06-23T12:00:02Z  
- **Event:** A user reported downloading the installer.  
- **Action:** Multiple Tor files copied, including `lor-shopping-list.txt`.  
- **Note:** File download path implied.

---

## 👤 User-Reported Tor Browser Use
- **Timestamp:** 2025-06-23T12:00:34Z  
- **Event:** User reported opening the browser.  
- **Action:** Multiple Tor processes observed.  

---

## 🌐 User-Reported Connection to pisodes.com
- **Timestamp:** 2025-06-23T12:01:28Z  
- **Event:** Verified repeated connection to known domain.  
- **Action:** Tor network connection established.  
- **Remote IP:** `192.87.28.28`  
- **Port(s):** `9001`, `443`  
- **Remote URL:** `https://www.pisodes.com`

---

> **🔐 Security Note:**  
> The observed timeline reflects clear evidence of Tor browser installation, execution, connection establishment, and use. Suspicious file creation events may warrant further investigation. Refer to DFIR procedures for deeper forensic analysis.

---

## Summary

Summary of Events:
The threat hunt identified a series of activities related to Tor browser usage on the cwav3-test-mde device, primarily by the cwav3 user account (also referred to as employee in some user-provided logs).

The sequence of events began on June 23, 2025, around 7:59 AM, with the initiation and silent installation of the Tor browser installer (tor-browser-windows-x86_64-portable-14.5.3.exe) from the user's downloads folder. This installation process created numerous essential Tor-related files and a desktop shortcut for the browser. Simultaneously, a potentially suspicious file named tor-shopping-list.txt and its shortcut were also created on the desktop, which warrants further investigation.

Following the installation, from approximately 8:00 AM to 8:06 AM, the Tor browser was actively launched, leading to the creation of multiple firefox.exe and tor.exe processes, indicating consistent user interaction with the application.

Network analysis revealed that the Tor browser successfully established connections through known Tor ports (specifically port 9001) to several external IP addresses and domains. Key connections included 114.23.164.80, 192.121.108.237 (for xpbyntjqh6wvlaglxaji2k.com), and 192.87.28.28 (for pisodes.com). Additional connections over port 443 were also observed, which is a common port for HTTPS traffic, but could also be used by Tor.

In conclusion, the investigation confirms the download, installation, and active use of the Tor browser on the cwav3-test-mde system, along with associated network communications. The presence of tor-shopping-list.txt alongside Tor browser activity suggests a potential area for deeper scrutiny.


---

## Response Taken

TOR usage was confirmed on endpoint cwav3-test-mde  by the user employee. The device was isolated and the user's direct manager was notified.

---
