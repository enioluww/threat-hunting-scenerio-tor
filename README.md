# Official Threathunting Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/enioluww/threat-hunting-scenerio-tor/blob/main/threat-hunting-scenario-tor-event-creation)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-10-06T04:19:07.2108098Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-sce"
|where RequestAccountName == "tenable_user"
| where FileName contains "tor"
|where TimeGenerated >= datetime('2025-10-06T03:42:52.1454965Z')
| order by TimeGenerated desc 
|project TimeGenerated, DeviceName, ActionType , FileName, SHA256, account = InitiatingProcessAccountName
```
<img width="1162" height="626" alt="Screenshot 2025-10-06 at 12 08 00 AM" src="https://github.com/user-attachments/assets/b3f568d5-b12e-424c-8674-af585b22fe97" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-10-06T03:56:17.5302926Z`, an employee on the "THREAT-HUNT-SCE" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-sce"
| where FileName == "tor-browser-windows-x86_64-portable-14.5.7.exe"
| project TimeGenerated, DeviceName, ActionType, AccountName, FileName, FolderPath,SHA256, ProcessCommandLine
```
<img width="1150" height="367" alt="Screenshot 2025-10-06 at 12 11 50 AM" src="https://github.com/user-attachments/assets/98560ca5-e560-43d8-a9bd-e487d50abf60" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that the user "tenable-user" actually opened the TOR browser. There was evidence that they did open it at `2025-10-06T05:20:17.4172028Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-sce"
| where FileName has_any ("tor.exe", "firefox.exe","tor-browser.exe")
| project TimeGenerated, DeviceName, ActionType, AccountName, FileName, FolderPath,SHA256, ProcessCommandLine

```
<img width="1163" height="501" alt="Screenshot 2025-10-06 at 12 13 56 AM" src="https://github.com/user-attachments/assets/71403201-038f-467d-8328-d808691587f3" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication that the TOR browser was used to establish a connection using any of the known TOR ports. At ` 2025-10-06T04:12:48.8896694Z,`, an employee on the "THREAT-HUNT-SCE" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-sce"
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151","443","80")
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessVersionInfoCompanyName
```
<img width="1163" height="560" alt="Screenshot 2025-10-06 at 12 15 58 AM" src="https://github.com/user-attachments/assets/b72b02f9-1662-4f99-b112-8fd0b613a608" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-10-06T04:19:07.2108098Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-10-06T03:56:17.5302926Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-10-06T05:20:17.4172028Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-10-06T04:12:48.8896694Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-sce` by the user `tenable-user`. The device was isolated, and the user's direct manager was notified.

---
