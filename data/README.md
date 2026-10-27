# Explainable AI SOC — Data Directory

This directory stores persistent databases, benchmark network flow datasets, and session summaries for the **Explainable AI Network Security SOC** platform.

---

## 📁 Directory Structure & File Manifest

| File | Type | Description |
| :--- | :--- | :--- |
| `soc_auth.db` | **SQLite Database** | Persistent authentication store: salted bcrypt password hashes, RBAC roles (`admin`, `analyst`), user approval queue, rate-limiting counters, and session logs. |
| `network_flow_windows.csv` | **Dataset (CSV)** | 600 continuous 30-second evaluation windows across 60 network captures. Contains 22 statistical flow features, ground truth labels, model probabilities, and SHAP feature importance vectors. |
| `session_summaries.csv` | **Telemetry (CSV)** | Aggregated 5-minute capture session summaries (20 Human, 20 Bot, 20 AI-Agent) including client IPs, payload volumes, average concurrency, and timing entropy. |

---

## 🛡️ Authentication Database (`soc_auth.db`)
Managed by [`auth_db.py`](../auth_db.py) via SQLAlchemy:
* **Default Admin Account:** `admin` / `admin123` (Lead Security / ML Engineer — Level 5 Clearance, raw IPs, user governance)
* **Default Analyst Account:** `analyst` / `analyst123` (Tier-2 SOC Analyst — Operational triage, masked IPs, read-only ML)
* **Security Controls:**
  * Password hashing: 12-round salted bcrypt (`bcrypt.hashpw`)
  * Rate-limiting: 5 maximum failed login attempts with automatic 15-minute account lockout
  * User registration approval queue with administrative approval/rejection workflows

---

## 📊 Dataset Schema (`network_flow_windows.csv`)
Each record represents a 30-second sliding slice evaluated by the LightGBM classifier:
* **Identification:** `window_id`, `session_id`, `window_idx`
* **Network Features:**
  * `timing_entropy`: Shannon entropy of inter-arrival delays
  * `concurrent_flows_max`: Peak parallel active connections
  * `burstiness`: Normalized variance-to-mean clustering metric
  * `in_out_ratio`: Ratio of incoming to outgoing payload bytes
  * `std_gap` / `mean_gap`: Standard deviation and mean of inter-request pauses
  * `total_packets`, `total_bytes`, `bytes_in`, `bytes_out`
  * `mean_flow_duration_ms`, `unique_dst_ips`, `unique_sni`, `pct_tls`
* **Classifier Outputs:**
  * `true_class`: Ground truth (`HUMAN`, `BOT`, `AI-AGENT`)
  * `predicted_class`: Model prediction
  * `confidence`: Top class probability $[0.0, 1.0]$
  * `is_uncertain`: Boolean flag (`True` when confidence $< 0.65$)
  * `prob_human`, `prob_bot`, `prob_agent`: Tri-class probability distribution
