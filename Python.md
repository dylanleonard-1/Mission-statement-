
## CsvGenX – Automated Risk Engine

---

### CsvGenX – Engine Visualization

![CsvGenX Engine Diagram](https://github.com/dylanleonard-1/Mission-statement-/blob/main/410AB3ED-0D78-45F4-B616-2F782C13C953.jpeg)

> *Above: A visual breakdown of CsvGenX – the autonomous risk generator that feeds SQL, Splunk, Power BI, and Excel pipelines with realistic CVE data.*

---

CsvGenX is the autonomous CVE and vendor simulation tool built inside the **CyberSec Warfare** platform. It creates realistic records of vulnerabilities, simulates risk across global vendors, enriches the results, and exports the data into SQL, Excel, Splunk, and Power BI pipelines.

---

### Core Capabilities

- Generates fake but realistic CVEs and vendor metadata  
- Adds AI-based enrichment: CVSS score, MTTR, patch status, etc.  
- Sends data to SQL Server, SQLite, JSON, and Power BI  
- Supports raw or enriched data flows based on flags  
- Simulates dirty/clean datasets with trend detection  

---

### Data Pools

| Pool Type        | File                        | Description                                  |
|------------------|-----------------------------|----------------------------------------------|
| Vendor Pool      | `vendors.csv`               | Company names, sectors, regions, contacts    |
| CVE Pool         | `vuln_pool_100.csv`         | Sample vulnerabilities with CVSS/descriptions|
| Scenario Pool    | `scenario_templates.csv`    | Exposure, MTTR, complexity simulation logic  |

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
| `python3 CsvGenX.py --seed 42 --count 50` | Deterministic run |

---

### Sample Output Reports

| Type | Description | Link |
|------|-------------|------|
| **Enriched Excel Report** | Includes CVE, CVSS, MTTR, patch info | [View](https://1drv.ms/x/c/5ffba468ae197aa5/Ef4JTcHCCq5BgWC27z6VpfgB4J0PQyUT2bEZwhnBaMRGoA?e=9R7jZQ) |
| **Raw Excel Report** | Vendor data only (unenriched) | [View](https://1drv.ms/x/c/5ffba468ae197aa5/EaHtOdCYZq5CggDNubs_nM4BMjdO1-DuPhemMe-DXqLjRA?e=DuedTN) |

---

### Code Flow: Data Generation → Enrichment → Export

#### 1. Vendor Sampling by Sector
```python
def sample_vendor_from_sector(sector):
    sector_vendors = vendor_data[vendor_data["Sector"] == sector]
    return sector_vendors.sample(1).iloc[0] if not sector_vendors.empty else vendor_data.sample(1).iloc[0]
```

---

### Healthy vs Vulnerable Split
```
healthy_ratio = random.uniform(0.3, 0.7)
num_good = int(count * healthy_ratio)
```

---

### CVE Assignment & Risk Injection

```
if is_good:
    record = {
        "vendor": vendor["Vendor_Name"],
        "risk": "None",
        "cve_id": "N/A",
        "cvss_score": 0,
        ...
    }
else:
    vuln = vuln_data.sample(1).iloc[0]
    scenario = scenario_data.sample(1).iloc[0]
    record = {
        "vendor": vendor["Vendor_Name"],
        "risk": scenario["Risk_Level"],
        "cve_id": vuln["Vuln_ID"],
        ...
    }
```

---

### Trend Spike Detection

```
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

### SQL Server Injection (pyodbc)

```
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

### Splunk Export – JSON Logger

```
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
| `threatquery.db` | SQLite for local ingestion       |
| SQL Server       | Reporting backend                |
| Splunk JSON      | Alert + trend log simulation     |

---

