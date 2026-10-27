import pandas as pd
import matplotlib.pyplot as plt
import json
import requests
import time

plt.rcParams["text.parse_math"] = False

# --- Baca log & ambil IP unik (tanpa IP sendiri) ---
events = []
with open("cowrie.json", "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass

df = pd.DataFrame(events)
MY_IP = "180.252.89.160"
df = df[df["src_ip"] != MY_IP]

ip_counts = df["src_ip"].value_counts()
unique_ips = ip_counts.index.tolist()
print(f"Melihat lokasi {len(unique_ips)} IP penyerang...")

# --- Lookup GeoIP via ip-api.com (batch, gratis, tanpa key) ---
geo_results = []
for i in range(0, len(unique_ips), 100):  # batch maks 100 per request
    batch = [{"query": ip} for ip in unique_ips[i:i+100]]
    resp = requests.post(
        "http://ip-api.com/batch?fields=query,status,country,countryCode,isp",
        json=batch
    )
    geo_results.extend(resp.json())
    time.sleep(1)

geo_df = pd.DataFrame(geo_results)
geo_df = geo_df[geo_df["status"] == "success"]

# --- Gabung jumlah serangan + info negara ---
geo_df["attacks"] = geo_df["query"].map(ip_counts)
geo_df = geo_df.sort_values("attacks", ascending=False)

# Simpan tabel ke CSV (buat README nanti)
geo_df[["query", "country", "isp", "attacks"]].to_csv("ip_enrichment.csv", index=False)
print("Tersimpan: ip_enrichment.csv")
print("\n=== Ringkasan IP Penyerang ===")
print(geo_df[["query", "country", "isp", "attacks"]].to_string(index=False))

# --- Grafik: serangan per negara ---
by_country = geo_df.groupby("country")["attacks"].sum().sort_values(ascending=True)
plt.figure(figsize=(10, 6))
by_country.plot(kind="barh", color="#16a085")
plt.title("Serangan per Negara", fontsize=14, fontweight="bold")
plt.xlabel("Jumlah Event")
plt.tight_layout()
plt.savefig("06_attacks_by_country.png", dpi=120)
print("\nTersimpan: 06_attacks_by_country.png")