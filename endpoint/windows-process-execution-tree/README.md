# Windows & Sysmon Process Tree Reconstruction (Classic Dashboard SPL)

A production-ready Splunk SPL query designed for **Classic Dashboards** to reconstruct Parent-Child process execution lineages using both native Windows Security auditing and Sysmon event logs.

---

## 🎯 Use Case & Forensic Purpose

During alert triage and DFIR investigations, analysts need to see the entire execution hierarchy of an endpoint rather than isolated events:
* **Webshell & Exploitation Tracing**: Detecting abnormal parentage like `w3wp.exe` spawning compilers (`csc.exe`) or command shells (`cmd.exe`, `powershell.exe`).
* **LOLBin Activity**: Tracing Living-off-the-Land binaries and their argument payloads.
* **Privilege Context**: Correlating executing users and command-line parameters across the process lineage.

---

## ⚙️ Data Sources & Event IDs

| Data Source | EventCode | Key Ingested Fields |
| :--- | :--- | :--- |
| **Microsoft Windows Security** | `4688` | `process_id` (Hex), `parent_process_id` (Hex), `process_path` |
| **Microsoft-Windows-Sysmon** | `1` | `CommandLine`, `OriginalFileName`, `user` |

---

## 🧩 Technical Highlights

1. **Dual-Source Correlation**: Integrates Windows `4688` and Sysmon `1` into a single, cohesive timeline.
2. **Hex-to-Dec PID Normalization**: Windows `4688` logs PIDs in hexadecimal (`0x160356`), whereas Sysmon and SOC analysts typically reference decimal integers. The query uses `tonumber(..., 16)` to normalize PIDs for accurate parent-child matching.
3. **PE Masquerading Mitigation**: Inspects `OriginalFileName` to catch renamed binaries attempting defense evasion.
4. **Visual Hierarchy**: Utilizes the `pstree` custom command to render structured tree branches directly in a dashboard table.

---

## 📋 Prerequisites

To render the visual hierarchy, ensure the following search command is available in your Splunk environment:
* **[pstree Custom Search Command](https://splunkbase.splunk.com/)** (available via Splunkbase).

---

## 🚀 Setting up in a Classic Dashboard

You can drop this SPL directly into a Splunk **Classic Dashboard (Simple XML)** panel using standard UI inputs:

### 1. Dashboard Form Inputs (Tokens)
Configure the following inputs in your dashboard header:

| Input Type | Token Name | Default Value | Description |
| :--- | :--- | :--- | :--- |
| **Time Range** | Default Splunk Timepicker | Last 24 Hours | Scopes the query execution window |
| **Text** | `host` | `*` | Target machine hostname (e.g., `APAMLAKTEHRAN61`) |
| **Text** | `process_path` | `*` | Path/Executable filter regex or wildcard |
| **Text** | `process_id` | `*` | Target Process ID filter (Decimal or Hex) |

> *Tip: If running directly in "Search & Reporting" outside of a dashboard, simply replace tokens like `$host$`, `$process_path$`, and `$process_id$` with wildcards (`*`) or specific target values.*

### 2. Add Panel
1. Create or edit an existing **Classic Dashboard**.
2. Add a new **Statistics Table** panel.
3. Paste the contents of [`process_tree.spl`](./process_tree.spl) into the search query box.
4. Set the panel search to listen to the shared timepicker and input tokens.

---

## 🖥️ Expected Output

The table renders an interactive ASCII process tree with execution timestamps, event source IDs, user context, and command lines:
```text
tree
------------------------------------------------------------------------------------------------------------------------------------------------------------
w3wp.exe (PID: 104790)
|--- csc.exe (PID: 160356)       2026-09-28 15:09:29 (EventID 1) (User: EstateMain-100) "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig ...
