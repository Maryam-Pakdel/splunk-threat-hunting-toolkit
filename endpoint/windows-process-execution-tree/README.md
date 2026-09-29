# Windows & Sysmon Process Tree Reconstruction

A forensic-grade Splunk SPL query designed to correlate and reconstruct end-to-end execution hierarchies (Parent-Child Process Trees) using both native Windows Security auditing and Sysmon logs.

---

## 🎯 Purpose & Use Cases

During DFIR (Digital Forensics and Incident Response) and SOC alert triage, analysts frequently need to inspect process lineage to detect:
* **Living-off-the-Land Binaries (LOLBins)** spawned by atypical parents (e.g., `w3wp.exe` launching `cmd.exe` or `csc.exe`).
* Malicious execution flows from initial access down to payload staging.
* In-depth command-line arguments across the process lineage.

This query aggregates process events, normalizes identifiers across differing data sources, resolves execution chains, and renders an ASCII visual process tree.

---

## ⚙️ Data Sources & Event IDs

| Data Source | EventCode | Description |
| :--- | :--- | :--- |
| **Microsoft Windows Security** | `4688` | A new process has been created |
| **Microsoft-Windows-Sysmon** | `1` | Process creation |

---

## 🧩 Key Technical Capabilities

1. **Dual Source Correlation**: Blends Windows Security `4688` and Sysmon `1` events into a unified timeline.
2. **PID Normalization**: In native Windows `4688` events, `ProcessId` and `ParentProcessId` are logged as hexadecimal strings (e.g., `0x27244`). The query automatically converts them to decimal integers via `tonumber(..., 16)` to ensure seamless correlation with Sysmon and OS-level PID trackers.
3. **PE Metadata Fallback**: Resolves original executable names (`OriginalFileName`) when available to bypass masqueraded or renamed binary tactics.
4. **Visual Tree Rendering**: Employs the `pstree` command to compute parent-child edges and print indented process trees with full CLI and timestamp contexts.

---

## 📋 Prerequisites

To visualize the tree structure directly inside Splunk, ensure the following custom search command app is installed in your Splunk environment:
* **TA-pstree** or equivalent `pstree` custom search command available on [Splunkbase](https://splunkbase.splunk.com/).

---

## 🚀 How to Use

1. Open `process_tree.spl`.
2. Replace `<TARGET_HOST>` with the destination host name or pattern (e.g., `APAMLAKTEHRAN61`).
3. Replace `<TARGET_PID_OR_*>` with the specific decimal/hex PID under triage, or use `*` to trace the entire host tree.
4. Execute the query over the suspected incident time frame.

### Sample Output:
```text
tree
------------------------------------------------------------------------------------------------------
w3wp.exe (PID: 104790)
|--- csc.exe (PID: 160356)       2026-09-28 15:09:29 (EventID 1) (User: EstateMain-100) "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig ...

