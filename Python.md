# CsvGenX – AI-Powered Risk Simulation Engine  

![CsvGenX Engine Diagram](https://github.com/dylanleonard-1/Mission-statement-/blob/main/410AB3ED-0D78-45F4-B616-2F782C13C953.jpeg)

> **Above**: A visual breakdown of CsvGenX – the autonomous risk generator that feeds SQL, Splunk, Power BI, and Excel pipelines with realistic CVE data.

---

## Full Code Breakdown + How It Maps to ProcessUnity

Welcome to **CsvGenX**, the Python engine that simulates third-party risk workflows from scratch. It generates realistic CVEs, enriches them using AI-style logic, assigns them to fake vendors, and exports them into SQL, Power BI, and Splunk — just like **ProcessUnity** handles vendor risk scoring, SLA tracking, and alerting.

---

## 1. Data Pool Initialization

```python
vendor_data = pd.read_csv(VENDOR_POOL_PATH)
scenario_data = pd.read_csv(SCENARIO_POOL_PATH)
vuln_data = pd.read_csv(VULN_POOL_PATH)
```

**What it does:** Loads the intelligence base.  
**ProcessUnity Equivalent:** Think of this as your Vendor Profile intake (vendor registry), CVE feed (from NIST/CISA), and internal SLA & risk mappings.

---

## 2. CLI Argument Parsing

```python
parser = argparse.ArgumentParser()
parser.add_argument("--seed", type=int)
parser.add_argument("--unenriched", action="store_true")
parser.add_argument("--count", type=int, default=50)
parser.add_argument("--nosql", action="store_true")
parser.add_argument("--nojson", action="store_true")
```

**What it does:** Adds command-line options so you can simulate different ingestion environments.  
**ProcessUnity Equivalent:** Mirrors toggles or rules (e.g., auto-classification off, alert suppression, SLA skip).

---

## 3. Vendor Sampling Logic

```python
def sample_vendor_from_sector(sector):
    sector_vendors = vendor_data[vendor_data["Sector"] == sector]
    return sector_vendors.sample(1).iloc[0] if not sector_vendors.empty else vendor_data.sample(1).iloc[0]
```

**What it does:** Dynamically selects a vendor based on sector distribution.  
**ProcessUnity Equivalent:** When uploading or reviewing risks, vendors are pulled by category or business unit.

---

## 4. Risk Split Logic – Clean vs Vulnerable

```python
healthy_ratio = random.uniform(0.3, 0.7)
num_good = int(count * healthy_ratio)
```

**What it does:** Creates a split between vendors with no vulnerabilities and those with risks.  
**ProcessUnity Equivalent:** This mimics real dashboards where many vendors are clean, but high-risk ones trigger SLA or investigation paths.

---

## 5. CVE Enrichment and Assignment

```python
if is_good:
    record = {
        "risk": "None", "cve_id": "N/A", "cvss_score": 0,
        "description": "No vulnerabilities detected."
    }
else:
    vuln = vuln_data.sample(1).iloc[0]
    scenario = scenario_data.sample(1).iloc[0]
    record = {
        "risk": scenario["Risk_Level"],
        "cve_id": vuln["Vuln_ID"],
        "cvss_score": vuln["CVSS_Score"],
        "description": vuln["Description"],
        "mttr": scenario["MTTR_Range"]
    }
```

**What it does:** Adds AI-style logic to determine if the vendor has an exploitable CVE.  
**ProcessUnity Equivalent:** Simulates vendor-specific vulnerability intake, matching findings to profiles + risk logic.

---

## 6. Trend Spike Detection

```python
def generate_trend_data(records):
    dirty = [r for r in records if r["risk"] != "None"]
    region = Counter([r["region"] for r in dirty])
    sector = Counter([r["sector"] for r in dirty])
    return {
        "region_spike": region.most_common(1)[0][0] if region else "N/A",
        "sector_spike": sector.most_common(1)[0][0] if sector else "N/A",
        "new_cve": dirty[0]["cve_id"] if dirty else "N/A"
    }
```

**What it does:** Finds sectors or regions with sudden vulnerability spikes.  
**ProcessUnity Equivalent:** These are your dynamic dashboards and trending widgets that detect systemic risk (e.g., “Defense vendors with critical CVEs in Asia”).

---

## 7. SQL Server Injection via pyodbc

```python
conn = pyodbc.connect(SQL_CONN_STRING)
cursor = conn.cursor()
for _, row in df.iterrows():
    cursor.execute("""
        INSERT INTO CVE_Reports (
            vendor, cve_id, cvss_score, exploit_available, sector,
            contact_email, report_date, enriched, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        row['vendor'], row['cve_id'], row['cvss_score'],
        1 if row['exposure_confirmed'] == 'Yes' else 0,
        row['sector'], row['contact_email'],
        row['detection_date'], int(row['enriched']), row['description'])
conn.commit()
conn.close()
```

**What it does:** Inserts the records into SQL Server with full metadata.  
**ProcessUnity Equivalent:** Same as feeding records into a backend or data warehouse that powers compliance dashboards.

---

## 8. Splunk JSON Log Export

```python
with open(json_path, "w") as f:
    json.dump({
        "cve_records": df.to_dict(orient="records"),
        "trend_summary": generate_trend_data(df.to_dict(orient="records"))
    }, f, indent=4)
```

**What it does:** Sends structured JSON to be picked up by Splunk for indexing, alerting, and visualization.  
**ProcessUnity Equivalent:** Just like sending alerts to a SIEM or storing vendor alerts for case creation.

---

## 9. Output Destinations

| Destination      | Purpose                         |
|------------------|----------------------------------|
| `inbox/*.csv`    | Power BI-ready logs              |
| `threatquery.db` | SQLite for local analysis        |
| SQL Server       | Persistent backend for dashboard |
| Splunk JSON      | Real-time SIEM integration       |

---

## 10. Final Execution Block

```python
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int)
    parser.add_argument("--unenriched", action="store_true")
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--nosql", action="store_true")
    parser.add_argument("--nojson", action="store_true")
    args = parser.parse_args()

    main(
        seed=args.seed,
        enriched=not args.unenriched,
        count=args.count,
        send_sql=not args.nosql,
        send_json=not args.nojson
    )
```

**What it does:** Launches the engine based on CLI flags.  
**ProcessUnity Equivalent:** Think of this as turning on or off ingestion jobs, deciding whether to sync to dashboards or just preview raw data.

---

## In Summary

CsvGenX mimics **ProcessUnity’s** architecture by:
- Generating vendor profiles and scoring logic dynamically
- Mapping CVEs to vendors and simulating exploitability
- Enriching records with AI-style metadata (MTTR, patching, CVSS)
- Logging data into long-term storage (SQL), short-term analytics (CSV), and alerting (Splunk)
- Supporting deterministic runs (via `--seed`) and flexibility for partial ingestion (`--nosql`, `--nojson`)

Use it as a training simulator, a mock ingestion tool, or a local SOC lab engine.
