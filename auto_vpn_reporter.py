import time
import os
import logging
import requests
from apscheduler.schedulers.background import BackgroundScheduler
from script import VPNConverter
from config import GITHUB_REPO, GITHUB_TOKEN, TEMPLATE_FILE, OUTPUT_PREFIX, DOWNLOAD_DIR
from vpn_tester import VPNTester
from country_flag import country_to_flag

TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]

# --- Setup logging ---
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)

converter = VPNConverter(
    github_repo=GITHUB_REPO,
    github_token=GITHUB_TOKEN,
    template_file=TEMPLATE_FILE,
    output_prefix=OUTPUT_PREFIX,
    download_dir=DOWNLOAD_DIR,
)
tester = VPNTester()

def extract_ip_port_from_account(cfg):
    # Prioritaskan real_server/real_port (patch untuk support IP di path)
    if "real_server" in cfg and "real_port" in cfg:
        return cfg["real_server"], cfg["real_port"]
    if "transport" in cfg and "path" in cfg["transport"]:
        path = cfg["transport"]["path"]
        import re
        m = re.match(r"/([\d\.]+)-(\d+)", path)
        if m:
            return m.group(1), int(m.group(2))
    if "path" in cfg:
        path = cfg["path"]
        import re
        m = re.match(r"/([\d\.]+)-(\d+)", path)
        if m:
            return m.group(1), int(m.group(2))
    return None, None

def send_telegram_message(msg):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": msg,
        "parse_mode": "HTML"
    }
    try:
        resp = requests.post(url, data=data, timeout=15)
        logging.info(f"Notif Telegram: {resp.status_code} {resp.text}")
        return resp.status_code == 200
    except Exception as e:
        logging.error(f"Gagal mengirim Telegram: {e}")
        return False

def scheduled_report():
    logging.info("Laporan hasil test node (semua node dengan IP/port di path):")
    files = converter.get_github_files()
    for fname in files:
        try:
            config = converter.get_file_from_github(fname)
            akun_lama = [o for o in config.get("outbounds", []) if o.get("type") in ["trojan", "vless", "vmess"]]
            notif_lines = [f"<b>File: {fname}</b>"]
            print(f"\n=== File: {fname} ===")
            for node in akun_lama:
                ip, port = extract_ip_port_from_account(node)
                if not ip or not port:
                    continue  # skip yang tidak ada IP/port di path
                provider = node.get('provider', '-') or '-'
                country = node.get('country', '-') or '-'
                tag = node.get('tag', '-') or '-'
                try:
                    result = tester.test_connection((ip, port))
                    flag = country_to_flag(country)
                    status = result.get("status", "-")
                    latency = result.get("latency", "-")
                    # Log ke konsol
                    print(f"{flag} {provider:12} | {ip:15} | {tag:20} | {status:10} | {latency}")
                    notif_lines.append(
                        f"{flag} <b>{provider}</b> | <code>{ip}</code> | <i>{tag}</i> | <b>{status}</b> | {latency}"
                    )
                except Exception as e:
                    print(f"{provider:12} | {ip:15} | {tag:20} | ERROR: {e}")
                    notif_lines.append(
                        f"{provider} | <code>{ip}</code> | {tag} | <b>ERROR</b>: {e}"
                    )
            notif_msg = "\n".join(notif_lines)
            # Jika node terlalu banyak, batasi panjang pesan agar tidak error
            if len(notif_msg) > 4000:
                notif_msg = notif_msg[:3990] + "\n(Potong: terlalu panjang)"
            send_telegram_message(notif_msg)
        except Exception as e:
            logging.error(f"ERROR membaca config {fname}: {e}")
            send_telegram_message(f"❌ ERROR membaca config <b>{fname}</b>: {e}")

if __name__ == "__main__":
    scheduler = BackgroundScheduler()
    scheduler.add_job(scheduled_report, 'interval', minutes=1)
    scheduler.start()
    logging.info("VPN reporter aktif, hasil dicek & dikirim ke telegram setiap menit.")
    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        logging.info("VPN reporter dihentikan.")