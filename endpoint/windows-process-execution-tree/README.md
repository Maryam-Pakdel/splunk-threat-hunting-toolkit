# Windows & Sysmon Process Tree Reconstruction (Classic Dashboard SPL)

A production-ready Splunk SPL query designed for **Classic Dashboards** to reconstruct Parent-Child process execution lineages using both native Windows Security auditing and Sysmon event logs.

---

## 🎯 Use Case & Forensic Purpose

During alert triage and DFIR investigations, analysts need to see the entire execution hierarchy of an endpoint rather than isolated events:
* **Webshell & Exploitation Tracing**: Detecting abnormal parentage like `w3wp.exe` spawning compilers (`csc.exe`) or command shells (`cmd.exe`, `powershell.exe`).
* **LOLBin Activity**: Tracing Living-off-the-Land binaries and their argument payloads.
* **Privilege Context**: Correlating executing users and command-line parameters across the process lineage.

---

## 📚 Recommended Reading
For a deeper understanding of the tradecraft, methodology, and the "why" behind process tree analysis, I highly recommend reading:
* **[Process Hunting with a Process Tree](https://www.splunk.com/en-us/blog/security/process-hunting-with-a-process.html)** - An insightful Splunk blog post that explores the value of process lineage visibility in SOC operations and how it elevates threat hunting capabilities.

---

## ⚙️ Data Sources & Event IDs

| Data Source | EventCode | Key Ingested Fields |
| :--- | :--- | :--- |
| **Microsoft Windows Security** | `4688` | `process_id` (Hex), `parent_process_id` (Hex), `process_path` |
| **Microsoft-Windows-Sysmon** | `1` | `CommandLine`, `OriginalFileName`, `user`, `ProcessGuid` |

---

## 🧩 Technical Highlights

1. **Dual-Source Correlation**: Integrates Windows `4688` and Sysmon `1` into a single, cohesive timeline.
2. **Hex-to-Dec PID Normalization**: Windows `4688` logs PIDs in hexadecimal (`0x27244`), whereas Sysmon and SOC analysts typically reference decimal integers. The query uses `tonumber(..., 16)` to normalize PIDs for accurate parent-child matching.
3. **PE Masquerading Mitigation**: Inspects `OriginalFileName` to catch renamed binaries attempting defense evasion.
4. **Visual Hierarchy**: Utilizes the `pstree` custom command to render structured tree branches directly in a dashboard table.

---

## 📋 Prerequisites

To render the visual hierarchy, ensure the following search command is available in your Splunk environment:
* **[pstree Custom Search Command](https://splunkbase.splunk.com/)** (available via Splunkbase).

---

## 🛠️ Classic Dashboard Input Tokens

All dashboard input tokens are **optional**. When left blank or set to default wildcards (`*`), the dashboard dynamically inspects the full scope within the chosen time window.

| Input Token | UI Input Type | Default | Optional | Description |
| :--- | :--- | :--- | :--- | :--- |
| `time` | TimeRangePicker | Last 1 Hours | No | Scopes the forensic timeframe |
| `host` | Text Box | `*` | Yes | Target endpoint hostname |
| `user` | Text Box | `*` | Yes | Target username or domain account |
| `process_path` | Text Box | `*` | Yes | Process binary name or full path |
| `ProcessGuid` | Text Box | `*` | Yes | Sysmon unique Process GUID |
| `process_id` | Text Box | `*` | Yes | Specific PID filter |

---

## 🚀 Setting up in a Classic Dashboard

1. Navigate to **Dashboards** > **Create New Dashboard** in Splunk.
2. Select **Classic Dashboard (Simple XML)**.
3. Add the input fields (Time, Text inputs for Host, User, Process Path, ProcessGuid, and PID).
4. Add a new **Statistics Table** panel.
5. Paste the contents of [`process_tree.spl`](./process_tree.spl) into the panel search.
6. Connect the search tokens to your form inputs.

> *Note: If running as a standalone ad-hoc search in Search & Reporting, replace tokens like `$host$`, `$user$`, `$process_path$`, `$ProcessGuid$`, and `$process_id$` with wildcards (`*`) or specific forensic artifacts.*

---

## 🖥️ Expected Output Example

The table renders an interactive ASCII process tree with execution timestamps, event source IDs, user context, and command lines:
```text
tree
------------------------------------------------------------------------------------------------------------------------------------------------------------
w3wp.exe (PID: 104790)
|--- csc.exe (PID: 160356)       2026-09-28 15:09:29 (EventID 1) (User: CORP\svc-iis) "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig ...
