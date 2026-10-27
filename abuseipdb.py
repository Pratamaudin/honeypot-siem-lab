import pandas as pd
import matplotlib.pyplot as plt
import requests
import time

plt.rcParams["text.parse_math"] = False

# --- Baca API key dari file lokal (tidak di-commit ke GitHub) ---
with open("apikey.txt", "r") as f:
    API_KEY = f.read().strip()

# --- Ambil daftar IP + jumlah serangan dari hasil GeoIP sebelumnya ---
geo = pd.read_csv("ip_enrichment.csv")

headers = {"Key": API_KEY, "Accept": "application/json"}
results = []

print(f"Mengecek reputasi {len(geo)} IP di AbuseIPDB...")
for ip in geo["query"]:
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers=headers,
        params={"ipAddress": ip, "maxAgeInDays": 90}
    )
    data = resp.json().get("data", {})
    results.append({
        "query": ip,
        "abuseScore": data.get("abuseConfidenceScore"),
        "totalReports": data.get("totalReports"),
        "isWhitelisted": data.get("isWhitelisted"),
    })
    time.sleep(1)  # sopan ke API

abuse_df = pd.DataFrame(results)

# --- Gabung dengan data GeoIP ---
merged = geo.merge(abuse_df, on="query")
merged = merged.sort_values("attacks", ascending=False)
merged.to_csv("ip_enrichment_full.csv", index=False)

print("\n=== IP Penyerang + Reputasi AbuseIPDB ===")
print(merged[["query", "country", "attacks", "abuseScore", "totalReports"]].to_string(index=False))
print("\nTersimpan: ip_enrichment_full.csv")

# --- Grafik: skor abuse untuk top 10 penyerang ---
top10 = merged.head(10)
plt.figure(figsize=(10, 6))
colors = ["#c0392b" if s >= 50 else "#e67e22" for s in top10["abuseScore"]]
plt.barh(top10["query"][::-1], top10["abuseScore"][::-1], color=colors[::-1])
plt.title("Skor Reputasi AbuseIPDB (Top 10 Penyerang)", fontsize=14, fontweight="bold")
plt.xlabel("Abuse Confidence Score (0-100)")
plt.xlim(0, 100)
plt.tight_layout()
plt.savefig("07_abuse_scores.png", dpi=120)
print("Tersimpan: 07_abuse_scores.png")