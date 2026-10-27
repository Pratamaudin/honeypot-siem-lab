import pandas as pd
import matplotlib.pyplot as plt
import json

plt.rcParams["text.parse_math"] = False

# --- Baca perintah penyerang dari log ---
cmds = []
with open("cowrie.json", "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("eventid") == "cowrie.command.input" and e.get("src_ip") != "180.252.89.160":
            cmds.append(e.get("input", ""))

print(f"Total perintah dianalisis: {len(cmds)}")

# --- Pemetaan teknik MITRE berdasarkan pola perintah (hasil analisis) ---
techniques = {
    "T1110 Brute Force": lambda c: False,  # dihitung terpisah (dari event login)
    "T1059.004 Unix Shell": lambda c: c.startswith("sh -c") or c.startswith("printf"),
    "T1098.004 SSH Authorized Keys": lambda c: "authorized_keys" in c,
    "T1222.002 File Permissions Mod": lambda c: "chattr" in c or "chmod" in c,
    "T1070.004 File Deletion": lambda c: "rm -rf" in c,
    "T1082 System Info Discovery": lambda c: "uname" in c or "$$" in c or "$((" in c,
    "T1105 Ingress Tool Transfer": lambda c: "setup.sh" in c or "clean.sh" in c or "wget" in c or "curl" in c,
}

# Hitung berapa perintah cocok tiap teknik
counts = {}
for name, match in techniques.items():
    counts[name] = sum(1 for c in cmds if match(c))

# Brute Force dihitung dari jumlah event login (bukan command) — isi manual dari datamu
counts["T1110 Brute Force"] = 3355  # ganti kalau jumlah login berbeda

# Buang teknik yang 0
counts = {k: v for k, v in counts.items() if v > 0}
series = pd.Series(counts).sort_values()

print("\n=== Teknik MITRE ATT&CK Teramati ===")
for k, v in series.sort_values(ascending=False).items():
    print(f"{v:>6}  {k}")

# --- Grafik ---
plt.figure(figsize=(11, 6))
series.plot(kind="barh", color="#34495e")
plt.title("Teknik MITRE ATT&CK yang Teramati di Honeypot", fontsize=14, fontweight="bold")
plt.xlabel("Jumlah Kemunculan (skala log)")
plt.xscale("log")
plt.tight_layout()
plt.savefig("08_mitre_attack.png", dpi=120)
print("\nTersimpan: 08_mitre_attack.png")