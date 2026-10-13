"""
Dev Dump Alert - Solana memecoin
Helius Enhanced Webhook -> filter -> Telegram

Mendeteksi:
  1. Transfer token dari dev wallet ke alamat exchange (CRITICAL)
  2. Transfer token dari dev wallet ke wallet lain (WARNING)
  3. Penjualan token oleh dev wallet via DEX/swap (CRITICAL)
"""
import hmac
import html
import logging
import os
from collections import OrderedDict

import requests
from flask import Flask, jsonify, request

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("dev-alert")

app = Flask(__name__)


def env_set(name):
    return {x.strip() for x in os.getenv(name, "").split(",") if x.strip()}


def env_labels(name):
    """Format: ADDR1:Binance,ADDR2:OKX  -> {ADDR1: Binance, ...}"""
    out = {}
    for item in os.getenv(name, "").split(","):
        item = item.strip()
        if not item:
            continue
        addr, _, label = item.partition(":")
        out[addr.strip()] = label.strip() or "Exchange"
    return out


TG_TOKEN = os.getenv("TG_TOKEN", "")
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
DEV_WALLETS = env_set("DEV_WALLETS")
MINTS = env_set("MINTS")  # kosong = semua token
EXCHANGES = env_labels("EXCHANGE_ADDRESSES")
MIN_AMOUNT = float(os.getenv("MIN_AMOUNT", "0"))  # jumlah token minimum untuk alert
LAMPORTS = 1_000_000_000

# Cegah alert ganda kalau Helius mengirim ulang (retry)
_seen = OrderedDict()
SEEN_MAX = 5000


def short(addr):
    return f"{addr[:4]}…{addr[-4:]}" if addr and len(addr) > 10 else str(addr)


def mint_ok(mint):
    return not MINTS or mint in MINTS


def fmt_num(x):
    return f"{x:,.2f}"


def send_telegram(text):
    if not TG_TOKEN or not TG_CHAT_ID:
        log.warning("TG_TOKEN / TG_CHAT_ID belum diisi. Pesan: %s", text)
        return
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            json={
                "chat_id": TG_CHAT_ID,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=10,
        )
        if not r.ok:
            log.error("Telegram error %s: %s", r.status_code, r.text)
    except requests.RequestException as e:
        log.error("Gagal kirim Telegram: %s", e)


def raw_amount(token_io):
    """Ambil jumlah token dari struktur tokenInputs/tokenOutputs (swap event)."""
    raw = token_io.get("rawTokenAmount") or {}
    try:
        return int(raw.get("tokenAmount", 0)) / (10 ** int(raw.get("decimals", 0)))
    except (ValueError, TypeError):
        return 0.0


def link(sig):
    return f"https://solscan.io/tx/{sig}"


def check_swap(tx, swap):
    alerts = []
    sig = tx.get("signature", "")
    for inp in swap.get("tokenInputs") or []:
        wallet, mint = inp.get("userAccount"), inp.get("mint", "")
        if wallet not in DEV_WALLETS or not mint_ok(mint):
            continue
        amt = raw_amount(inp)
        if amt < MIN_AMOUNT:
            continue

        # Hasil penjualan: SOL native atau token lain
        got = []
        nat = swap.get("nativeOutput") or {}
        if nat.get("account") in DEV_WALLETS:
            got.append(f"{int(nat.get('amount', 0)) / LAMPORTS:,.3f} SOL")
        for out in swap.get("tokenOutputs") or []:
            if out.get("userAccount") in DEV_WALLETS:
                got.append(f"{fmt_num(raw_amount(out))} (mint {short(out.get('mint'))})")
        got_txt = ", ".join(got) if got else "tidak diketahui"

        alerts.append(
            "🚨 <b>DEV JUAL (SWAP)</b>\n"
            f"Wallet: <code>{short(wallet)}</code>\n"
            f"Token: <code>{short(mint)}</code>\n"
            f"Jumlah: <b>{fmt_num(amt)}</b>\n"
            f"Diterima: {html.escape(got_txt)}\n"
            f"{link(sig)}"
        )
    return alerts


def check_transfers(tx):
    alerts = []
    sig = tx.get("signature", "")
    for t in tx.get("tokenTransfers") or []:
        src, dst, mint = t.get("fromUserAccount"), t.get("toUserAccount"), t.get("mint", "")
        if src not in DEV_WALLETS or not mint_ok(mint):
            continue
        if dst in DEV_WALLETS:  # pindah antar wallet dev sendiri, abaikan
            continue
        amt = float(t.get("tokenAmount") or 0)
        if amt < MIN_AMOUNT:
            continue

        if dst in EXCHANGES:
            alerts.append(
                "🚨 <b>DEV KIRIM KE EXCHANGE</b>\n"
                f"Exchange: <b>{html.escape(EXCHANGES[dst])}</b>\n"
                f"Dari: <code>{short(src)}</code>\n"
                f"Token: <code>{short(mint)}</code>\n"
                f"Jumlah: <b>{fmt_num(amt)}</b>\n"
                f"{link(sig)}"
            )
        else:
            alerts.append(
                "⚠️ <b>Dev transfer ke wallet lain</b>\n"
                f"Dari: <code>{short(src)}</code>\n"
                f"Ke: <code>{short(dst)}</code>\n"
                f"Token: <code>{short(mint)}</code>\n"
                f"Jumlah: <b>{fmt_num(amt)}</b>\n"
                "Bisa jadi wallet turunan atau deposit address exchange yang belum berlabel.\n"
                f"{link(sig)}"
            )
    return alerts


def handle_tx(tx):
    sig = tx.get("signature")
    if not sig or sig in _seen:
        return
    _seen[sig] = True
    if len(_seen) > SEEN_MAX:
        _seen.popitem(last=False)

    swap = (tx.get("events") or {}).get("swap")
    # Kalau ada swap event, transfer token di dalamnya sudah tercakup di check_swap
    alerts = check_swap(tx, swap) if swap else check_transfers(tx)
    for msg in alerts:
        send_telegram(msg)


@app.post("/hook")
def hook():
    if WEBHOOK_SECRET:
        auth = request.headers.get("Authorization", "")
        if not hmac.compare_digest(auth, WEBHOOK_SECRET):
            return jsonify(error="unauthorized"), 401

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify(error="invalid json"), 400
    txs = payload if isinstance(payload, list) else [payload]

    for tx in txs:
        try:
            handle_tx(tx)
        except Exception:  # jangan sampai satu tx rusak menggagalkan semuanya
            log.exception("Error memproses tx %s", tx.get("signature"))
    return jsonify(ok=True)


@app.get("/")
def health():
    return jsonify(
        status="running",
        dev_wallets=len(DEV_WALLETS),
        exchange_addresses=len(EXCHANGES),
        mints=len(MINTS),
    )


@app.post("/test")
def test():
    """Kirim pesan uji ke Telegram (dilindungi secret yang sama)."""
    if WEBHOOK_SECRET and not hmac.compare_digest(
        request.headers.get("Authorization", ""), WEBHOOK_SECRET
    ):
        return jsonify(error="unauthorized"), 401
    send_telegram("✅ Dev Dump Alert aktif.")
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
