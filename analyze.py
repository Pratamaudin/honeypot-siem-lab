import pandas as pd
import matplotlib.pyplot as plt
import json

# --- Baca cowrie.json (satu objek JSON per baris) ---
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
print(f"Total event terbaca: {len(df)}")

# --- Saring IP milik sendiri (trafik tes) ---
MY_IP = "180.252.89.160"
df = df[df["src_ip"] != MY_IP]
print(f"Event setelah menyaring IP sendiri: {len(df)}")
print(f"IP penyerang unik: {df['src_ip'].nunique()}")

plt.style.use("seaborn-v0_8-darkgrid")
plt.rcParams["text.parse_math"] = False

# --- Grafik 1: Top 10 IP penyerang ---
top_ip = df["src_ip"].value_counts().head(10)
plt.figure(figsize=(10, 6))
top_ip.sort_values().plot(kind="barh", color="#c0392b")
plt.title("Top 10 IP Penyerang", fontsize=14, fontweight="bold")
plt.xlabel("Jumlah Event")
plt.tight_layout()
plt.savefig("01_top_ip.png", dpi=120)
print("Tersimpan: 01_top_ip.png")

# --- Grafik 2: Top 10 password yang dicoba ---
login_df = df[df["eventid"].isin(["cowrie.login.success", "cowrie.login.failed"])]
if "password" in login_df.columns:
    top_pw = login_df["password"].value_counts().head(10)
    plt.figure(figsize=(10, 6))
    top_pw.sort_values().plot(kind="barh", color="#2980b9")
    plt.title("Top 10 Password yang Dicoba", fontsize=14, fontweight="bold")
    plt.xlabel("Jumlah Percobaan")
    plt.tight_layout()
    plt.savefig("02_top_password.png", dpi=120)
    print("Tersimpan: 02_top_password.png")

# --- Grafik 3: Top 10 username yang dicoba ---
if "username" in login_df.columns:
    top_user = login_df["username"].value_counts().head(10)
    plt.figure(figsize=(10, 6))
    top_user.sort_values().plot(kind="barh", color="#27ae60")
    plt.title("Top 10 Username yang Dicoba", fontsize=14, fontweight="bold")
    plt.xlabel("Jumlah Percobaan")
    plt.tight_layout()
    plt.savefig("03_top_username.png", dpi=120)
    print("Tersimpan: 03_top_username.png")

# --- Grafik 4: Perintah yang dijalankan penyerang ---
cmd_df = df[df["eventid"] == "cowrie.command.input"]
if len(cmd_df) > 0 and "input" in cmd_df.columns:
    top_cmd = cmd_df["input"].value_counts().head(10)
    plt.figure(figsize=(10, 6))
    top_cmd.sort_values().plot(kind="barh", color="#8e44ad")
    plt.title("Top 10 Perintah yang Dijalankan", fontsize=14, fontweight="bold")
    plt.xlabel("Jumlah")
    plt.tight_layout()
    plt.savefig("04_top_commands.png", dpi=120)
    print("Tersimpan: 04_top_commands.png")

# --- Grafik 5: Serangan per jam ---
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
by_hour = df.dropna(subset=["timestamp"]).set_index("timestamp").resample("1h").size()
plt.figure(figsize=(12, 5))
by_hour.plot(kind="line", marker="o", color="#e67e22")
plt.title("Aktivitas Serangan per Jam", fontsize=14, fontweight="bold")
plt.xlabel("Waktu")
plt.ylabel("Jumlah Event")
plt.tight_layout()
plt.savefig("05_attacks_per_hour.png", dpi=120)
print("Tersimpan: 05_attacks_per_hour.png")

print("\nSelesai! Semua grafik tersimpan di folder cowrie-analysis.")