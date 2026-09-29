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
* **[Process Hunting with a Process Tree](https://www.splunk.com/en-us/blog/security/process-hunting-with-a-process.html)** - An insightful Splunk blog post that explores the value of process lineage visibility in SOC operations.

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
## 🧠 Technical Deep Dive: `process_tree.spl` Logic

This section provides a granular breakdown of the SPL execution pipeline to assist analysts in debugging or extending the query.

### 1. Data Ingestion & Noise Suppression
The query begins by aggregating process creation events from two primary telemetry sources:
*   **EventCode 4688**: Native Windows Security Auditing.
*   **EventCode 1**: Microsoft Sysmon.
*   **Exclusion Layer**: A mandatory filter `parent_process_name!="*splunkd.exe*"` is applied early in the pipeline to prevent the search from being flooded by Splunk’s internal agent activity, ensuring only relevant system/user activity is analyzed.

### 2. Advanced Regex Token Handling
Unlike standard Splunk filters, this query implements a sophisticated **Dynamic Regex Translation** for the input tokens (`$TOKEN_PROCESS_PATH$` and `$TOKEN_PROCESS_ID$`):
*   **Wildcard Support**: It uses `replace(..., "\*", ".*")` to convert standard user wildcards (`*`) into Regex-compatible patterns.
*   **Escaping**: It handles Windows backslashes by escaping them (`\\\\` to `\\\\\\\\`) and removes whitespace to ensure the `match()` function doesn't fail due to formatting issues.
*   **Case Insensitivity**: The `(?i)` flag is prepended to the pattern, making the search case-insensitive for file paths.

### 3. PID & Field Normalization (The Multi-Source Bridge)
One of the core challenges in process tracing is the discrepancy between log formats:
*   **Hex-to-Dec Conversion**: Windows logs PIDs in Hex (e.g., `0x1a4`), while Sysmon and user inputs are typically Decimal. The query uses `tonumber(process_id, 16)` to normalize all PIDs to Decimal integers, enabling accurate `stats` grouping and parent-child matching.
*   **Command Line Coalescing**: Since Windows and Sysmon use different field names (`Process_Command_Line` vs `CommandLine`), the `coalesce()` function ensures the query captures the command-line arguments regardless of the log source.

### 4. Forensic Enrichment & Masquerading Detection
The query goes beyond simple logging by adding defensive logic:
*   **Binary Identification**: Using `rex`, it strips the full path to isolate the executable name (`ProcessName`).
*   **Masquerading Check**: It evaluates the `OriginalFileName` field (from Sysmon). If a malicious actor renames `powershell.exe` to `calc.exe`, the query detects this by prioritizing the `OriginalFileName` over the reported `ProcessName`, exposing the attempt at defense evasion.

### 5. Data Aggregation & Multi-Value Management
Since a single process execution might be captured by both Windows and Sysmon, the query uses `stats` to deduplicate:
*   **Timeline Preservation**: `max(_time)` captures the latest activity timestamp.
*   **Multi-Value Joining**: `mvjoin(EventCode, ",")` and `mvjoin(User, " / ")` ensure that if multiple sources report different users or event IDs for the same PID, the information is concatenated rather than overwritten.

### 6. Recursive Tree Reconstruction
The final stage prepares the data for the `pstree` visualization:
*   **Node Construction**: It builds unique strings for `parent` and `child` by concatenating the process name with its normalized PID (e.g., `cmd.exe (PID: 4432)`).
*   **Contextual Details**: The `detail` field is enriched with the timestamp, Event ID, and the full command line.
*   **Visualization**: The `pstree` command recursively iterates through these parent-child pairs to build the ASCII visual hierarchy, with `spaces=60` ensuring a clean layout for long command lines.


---

## 📋 Prerequisites

To render the visual hierarchy, ensure the following search command is available in your Splunk environment:
* **[pstree Custom Search Command](https://splunkbase.splunk.com/app/5721)** (available via Splunkbase).

---

## 🛠️ Classic Dashboard Input Tokens

The query utilizes Regex-based matching for its input tokens, allowing for partial matches or wildcard (`*`) searching.

| Input Token | UI Input Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `time` | TimeRangePicker | Last 1 Hours | Scopes the forensic timeframe |
| `host` | Text Box | `*` | Target endpoint hostname |
| `TOKEN_PROCESS_PATH` | Text Box | `*` | Regex/Wildcard filter for process path |
| `TOKEN_PROCESS_ID` | Text Box | `*` | Decimal PID filter (Wildcard support) |

---

## 🚀 Setting up in a Classic Dashboard

1. Navigate to **Dashboards** > **Create New Dashboard** in Splunk.
2. Select **Classic Dashboard (Simple XML)**.
3. Add the required input fields (Time, Text inputs for Host, Process Path, and PID).
4. Add a new **Statistics Table** panel.
5. Paste the optimized SPL query into the panel search, ensuring the tokens `$TOKEN_PROCESS_PATH$` and `$TOKEN_PROCESS_ID$` are correctly mapped to your input forms.

> *Note: If running as a standalone ad-hoc search in Search & Reporting, replace the tokens directly with `*` or your specific forensic values.*

---

## 🖥️ Expected Output Example

The table renders an interactive ASCII process tree with execution timestamps, event source IDs, user context, and command lines:
```text
tree
------------------------------------------------------------------------------------------------------------------------------------------------------------
w3wp.exe (PID: 104790)
|--- csc.exe (PID: 160356)       2026-09-28 15:09:29 (EventID 1) (User: svc-iis) "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig ...
