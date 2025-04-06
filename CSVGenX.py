import os
import random
import pandas as pd
import sqlite3
import pyodbc
import json
from datetime import datetime, timedelta
import argparse
from collections import Counter

# === CONFIG ===
# Update these paths as necessary
DB_PATH = "/opt/vendor_risk_lab/threatqueryx/db/threatquery.db"  # SQLite DB path on the host
SPLUNK_INGEST_PATH = "/opt/splunk/var/spool/splunk"  # Splunk ingestion path on the host
CSV_SAVE_DIR = "/home/dylan/vendor_risk_lab/inbox"  
VENDOR_POOL_PATH = "/opt/vendor_risk_lab/data/vendors.csv"  # Path to vendor data
SCENARIO_POOL_PATH = "/opt/vendor_risk_lab/data/scenario_templates.csv"  # Path to scenario templates
VULN_POOL_PATH = "/opt/vendor_risk_lab/data/vuln_pool_100.csv"  # Path to vulnerability pool

SQL_CONN_STRING = (
    "DRIVER={ODBC Driver 18 for SQL Server};"
    "SERVER=192.168.122.245,1433;"  # IP of Red Hat VM
    "DATABASE=CyberWarfare;"
    "UID=sa;"
    "PWD=Indira_5125**;"
    "TrustServerCertificate=yes;"
)

# === LOAD DATA ===
vendor_data = pd.read_csv(VENDOR_POOL_PATH)
scenario_data = pd.read_csv(SCENARIO_POOL_PATH)
vuln_data = pd.read_csv(VULN_POOL_PATH)

# === UTILITIES ===
def generate_last_contact():
    days_ago = random.randint(1, 100)
    return (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d"), days_ago

def generate_detection_delay():
    delay_days = random.randint(0, 30)
    return (datetime.now() - timedelta(days=delay_days)).strftime("%Y-%m-%d"), delay_days

def assign_criticality(_):
    return random.choice(["Tier 1 - Critical", "Tier 2 - Important", "Tier 3 - Standard"])

def generate_sector_distribution(sectors, total):
    raw = [random.randint(5, 25) for _ in sectors]
    total_pct = sum(raw)
    norm = [round(p * 100 / total_pct) for p in raw]
    return {sec: int(total * pct / 100) for sec, pct in zip(sectors, norm)}

def generate_trend_data(records):
    dirty = [r for r in records if r["risk"] != "None"]
    region = Counter([r["region"] for r in dirty])
    sector = Counter([r["sector"] for r in dirty])
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "region_spike": region.most_common(1)[0][0] if region else "N/A",
        "sector_spike": sector.most_common(1)[0][0] if sector else "N/A",
        "new_cve": dirty[0]["cve_id"] if dirty else "N/A",
        "description": dirty[0]["description"] if dirty else "N/A",
        "dirty_ratio": len(dirty),
        "clean_ratio": len(records) - len(dirty)
    }

# === MAIN CVE GENERATOR ===
def generate_cve_data(count=50, enriched=True):
    cve_data_list = []
    healthy_ratio = random.uniform(0.3, 0.7)
    num_good = int(count * healthy_ratio)
    sectors = vendor_data["Sector"].unique().tolist()
    sector_distribution = generate_sector_distribution(sectors, count)

    def sample_vendor_from_sector(sector):
        sector_vendors = vendor_data[vendor_data["Sector"] == sector]
        return sector_vendors.sample(1).iloc[0] if not sector_vendors.empty else vendor_data.sample(1).iloc[0]

    for sector, num in sector_distribution.items():
        for _ in range(num):
            is_good = num_good > 0 and (random.random() < healthy_ratio)
            vendor = sample_vendor_from_sector(sector)
            last_date, days_ago = generate_last_contact()
            detection_date, delay = generate_detection_delay()
            criticality = assign_criticality(vendor["Vendor_Name"])

            if is_good:
                num_good -= 1
                record = {
                    "vendor": vendor["Vendor_Name"],
                    "region": vendor["Region"],
                    "sector": vendor["Sector"],
                    "criticality": criticality,
                    "country": vendor["Country"],
                    "city": vendor["City"],
                    "latitude": vendor["Latitude"],
                    "longitude": vendor["Longitude"],
                    "contact_name": vendor["Contact_Name"],
                    "contact_email": vendor["Contact_Email"],
                    "risk": "None",
                    "cve_id": "N/A",
                    "description": "No current vulnerabilities reported.",
                    "cvss_score": 0,
                    "last_contact_date": last_date,
                    "days_since_last_contact": days_ago,
                    "detection_date": detection_date,
                    "detection_delay_days": delay,
                    "exposure_confirmed": "No",
                    "patch_available": "N/A",
                    "inject_complexity": "None",
                    "mttr": "0",
                    "enriched": enriched
                }
            else:
                vuln = vuln_data.sample(1).iloc[0]
                scenario = scenario_data.sample(1).iloc[0]
                record = {
                    "vendor": vendor["Vendor_Name"],
                    "region": vendor["Region"],
                    "sector": vendor["Sector"],
                    "criticality": criticality,
                    "country": vendor["Country"],
                    "city": vendor["City"],
                    "latitude": vendor["Latitude"],
                    "longitude": vendor["Longitude"],
                    "contact_name": vendor["Contact_Name"],
                    "contact_email": vendor["Contact_Email"],
                    "risk": scenario["Risk_Level"],
                    "cve_id": vuln["Vuln_ID"],
                    "description": vuln["Description"],
                    "cvss_score": vuln["CVSS_Score"],
                    "last_contact_date": last_date,
                    "days_since_last_contact": days_ago,
                    "detection_date": detection_date,
                    "detection_delay_days": delay,
                    "exposure_confirmed": scenario["Exposure_Confirmed"],
                    "patch_available": scenario["Patch_Available"],
                    "inject_complexity": scenario["Inject_Complexity"],
                    "mttr": scenario["MTTR_Range"],
                    "enriched": enriched
                }
            cve_data_list.append(record)

    return pd.DataFrame(cve_data_list)

# === MAIN EXECUTION ===
def main(seed=None, enriched=True, count=50, send_sql=True, send_json=True):
    if seed is not None:
        random.seed(seed)

    df = generate_cve_data(count=count, enriched=enriched)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    output_file = os.path.join(CSV_SAVE_DIR, f"PowerBI_CVE_Report_{timestamp}_{'Enriched' if enriched else 'Raw'}.csv")
    df.to_csv(output_file, index=False)
    print(f"✅ Power BI CSV file saved: {output_file}")

    try:
        conn = sqlite3.connect(DB_PATH)
        df.to_sql("cve_records", conn, if_exists="append", index=False)
        conn.close()
        print(f"🧠 Injected {len(df)} records into threatquery.db (cve_records)")
    except Exception as e:
        print(f"❌ Failed to insert into DB: {e}")

    if send_sql:
        try:
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
            print("📡 SQL Server injection complete")
        except Exception as e:
            print(f"❌ SQL Server error: {e}")

    if send_json:
        try:
            json_path = os.path.join(SPLUNK_INGEST_PATH, f"log_cve_data_{timestamp}.json")
            with open(json_path, "w") as f:
                json.dump({"cve_records": df.to_dict(orient="records"), "trend_summary": generate_trend_data(df.to_dict(orient="records"))}, f, indent=4)
            print(f"📄 JSON log saved: {json_path}")
        except Exception as e:
            print(f"❌ Failed to write JSON: {e}")

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
