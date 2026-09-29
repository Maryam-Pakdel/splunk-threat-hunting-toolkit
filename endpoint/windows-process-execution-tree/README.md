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

### 🧠 Logic Breakdown: `process_tree.spl`

This section details the internal mechanics of the `process_tree.spl` query, broken down by its operational phases:

1. **Data Ingestion & Filtering**: Merges Windows Security EventCode `4688` and Sysmon EventCode `1` logs, while explicitly filtering out `splunkd.exe` to reduce noise.
2. **Dynamic Token Processing**: Utilizes `match` and `replace` functions to parse the `$TOKEN_PROCESS_PATH$` and `$TOKEN_PROCESS_ID$` inputs. This allows for wildcard-supported regex matching, ensuring flexibility during investigations.
3. **PID Normalization**: Converts hexadecimal PIDs (common in `4688`) to decimal format using `tonumber(..., 16)`. This aligns the dataset, enabling successful parent-child relationship correlation across different log sources.
4. **Field Normalization & Enrichment**:
    * Standardizes `CommandLine` arguments by coalescing multiple potential field names.
    * Uses `rex` and `OriginalFileName` checks to extract clean executable names, mitigating defense evasion techniques involving renamed binaries.
5. **Hierarchy Rendering**: Prepares the data by constructing `parent` and `child` strings (containing PID and Name), then passes them to the `pstree` command to generate the final hierarchical visualization.

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
|--- csc.exe (PID: 160356)       2026-09-28 15:09:29 (EventID 1) (User: CORP\svc-iis) "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig ...
