```markdown
## CsvGenX – Automated Risk Engine

![CsvGenX Engine Diagram](https://github.com/dylanleonard-1/Mission-statement-/blob/main/410AB3ED-0D78-45F4-B616-2F782C13C953.jpeg)

> **Above**: A visual breakdown of CsvGenX – the autonomous risk generator that feeds SQL, Splunk, Power BI, and Excel pipelines with realistic CVE data.

---

CsvGenX is the AI-powered CVE and vendor simulation engine inside the **CyberSec Warfare** platform. It automates the generation of realistic vulnerability reports across global vendors using randomized logic, AI-style enrichment, and dynamic pipeline exports to Power BI, Splunk, and SQL backends.

---

### Core Capabilities

- Generates realistic CVEs, exposure risks, and vendor metadata  
- Enriches data with CVSS scores, MTTR windows, patch logic, etc.  
- Sends data to **SQL Server**, **SQLite**, **JSON for Splunk**, and **CSV for Power BI**  
- Fully customizable via CLI flags  
- Uses real-world simulation pools (vendors, CVEs, scenarios)  
- Detects spikes by sector, region, or vulnerability type  
- Supports reproducible runs (`--seed`) and raw-only modes (`--unenriched`)

---

### Data Pools (Simulation Intelligence)

| Pool Type        | File                        | Description                                  |
|------------------|-----------------------------|----------------------------------------------|
| Vendor Pool      | `vendors.csv`               | Company names, regions, sectors, contacts     |
| CVE Pool         | `vuln_pool_100.csv`         | Simulated vulnerabilities with CVSS scores   |
| Scenario Pool    | `scenario_templates.csv`    | Custom attack exposure logic, MTTR, patching |

```python
# Load Data Pools
vendor_data = pd.read_csv(VENDOR_POOL_PATH)
scenario_data = pd.read_csv(SCENARIO_POOL_PATH)
vuln_data = pd.read_csv(VULN_POOL_PATH)
```

---

### CLI Execution Flags

| Flag             | Description |
|------------------|-------------|
| `--count`        | Number of records to generate (default: 50) |
| `--unenriched`   | Skip enrichment logic (no MTTR, patch, etc.) |
| `--nosql`        | Disable SQL Server export |
| `--nojson`       | Disable Splunk JSON export |
| `--seed`         | Use fixed seed for reproducibility |

---

### Example Commands

| Command | Purpose |
|--------|---------|
| `python3 CsvGenX.py --count 100` | Full run: enriched + JSON + SQL |
| `python3 CsvGenX.py --count 75 --unenriched` | Raw data, no CVE enrichment |
| `python3 CsvGenX.py --nosql` | Skip SQL export |
| `python3 CsvGenX.py --nojson` | Skip Splunk export |
| `python3 CsvGenX.py --seed 42 --count 50` | Deterministic output |

---

### Sample Output Reports

| Type | Description | Link |
|------|-------------|------|
| **Enriched Excel Report** | Includes CVE, CVSS, MTTR, patch info | [View](https://1drv.ms/x/c/5ffba468ae197aa5/Ef4JTcHCCq5BgWC27z6VpfgB4J0PQyUT2bEZwhnBaMRGoA?e=9R7jZQ) |
| **Raw Excel Report** | Vendor metadata only (unenriched) | [View](https://1drv.ms/x/c/5ffba468ae197aa5/EaHtOdCYZq5CggDNubs_nM4BMjdO1-DuPhemMe-DXqLjRA?e=DuedTN) |

---

### Code Flow: Data Generation → Enrichment → Export

```python
# Import & Paths
import os, random, pandas as pd, sqlite3, pyodbc, json
from datetime import datetime, timedelta
from collections import Counter
```

```python
# Paths and SQL Connection
VENDOR_POOL_PATH = "/opt/vendor_risk_lab/data/vendors.csv"
SCENARIO_POOL_PATH = "/opt/vendor_risk_lab/data/scenario_templates.csv"
VULN_POOL_PATH = "/opt/vendor_risk_lab/data/vuln_pool_100.csv"

SQL_CONN_STRING = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=192.168.122.245,1433;"
    "DATABASE=CyberWarfare;"
    "UID=sa;"
    "PWD=Indira_5125**;"
    "TrustServerCertificate=yes;"
)
```

---

#### Vendor Sampling by Sector

```python
def sample_vendor_from_sector(sector):
    sector_vendors = vendor_data[vendor_data["Sector"] == sector]
    return sector_vendors.sample(1).iloc[0] if not sector_vendors.empty else vendor_data.sample(1).iloc[0]
```

---

#### Healthy vs Vulnerable Split

```python
healthy_ratio = random.uniform(0.3, 0.7)
num_good = int(count * healthy_ratio)
```

---

#### CVE Assignment & AI Enrichment

```python
if is_good:
    record = {
        "risk": "None", "cve_id": "N/A", "cvss_score": 0,
        "description": "No vulnerabilities detected.",
        ...
    }
else:
    vuln = vuln_data.sample(1).iloc[0]
    scenario = scenario_data.sample(1).iloc[0]
    record = {
        "risk": scenario["Risk_Level"],
        "cve_id": vuln["Vuln_ID"],
        "cvss_score": vuln["CVSS_Score"],
        "description": vuln["Description"],
        "mttr": scenario["MTTR_Range"],
        ...
    }
```

---

#### Trend Spike Detection Logic

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

---

#### SQL Server Injection (pyodbc)

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

---

#### Splunk Export – JSON Log

```python
with open(json_path, "w") as f:
    json.dump({
        "cve_records": df.to_dict(orient="records"),
        "trend_summary": generate_trend_data(df.to_dict(orient="records"))
    }, f, indent=4)
```

---

### Output Paths

| Destination      | Purpose                         |
|------------------|----------------------------------|
| `inbox/*.csv`    | Power BI-ready CVE logs          |
| `threatquery.db` | SQLite local ingestion           |
| SQL Server       | Real-time backend                |
| Splunk JSON      | Alert + trend simulation logs    |

---

### Final Execution Block

```python
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, help="Optional seed for repeatable results")
    parser.add_argument("--unenriched", action="store_true", help="Generate unenriched CVE records")
    parser.add_argument("--count", type=int, default=50, help="Number of records to generate")
    parser.add_argument("--nosql", action="store_true", help="Disable SQL Server injection")
    parser.add_argument("--nojson", action="store_true", help="Disable Splunk JSON export")
    args = parser.parse_args()

    main(
        seed=args.seed,
        enriched=not args.unenriched,
        count=args.count,
        send_sql=not args.nosql,
        send_json=not args.nojson
    )
```

---

<p align="center">
  <a href="#top">
    <img src="https://img.shields.io/badge/Home-000000?style=for-the-badge&logo=github&logoColor=white" alt="Home">
  </a>
  &nbsp;&nbsp;&nbsp;
  <a href="https://github.com/dylanleonard-1/vendor-risk-lab/blob/main/DaxForge_README.md">
    <img src="https://img.shields.io/badge/Next→-0A66C2?style=for-the-badge&logo=readme&logoColor=white" alt="Next">
  </a>
</p>
```
