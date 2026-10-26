#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
NOTIFICATION DASHBOARD & REALTIME MESSAGE HUB
------------------------------------------------------------------------------
A lightweight, self-contained dashboard for monitoring incoming notifications,
service alerts, and confirmation tokens in real-time.
- Background IMAP Sync Worker for realtime notification polling
- Built-in SQLite database for message indexing
- Embedded Glassmorphism Web Interface
- Realtime Server-Sent Events (SSE) updates
- RESTful JSON API
==============================================================================
"""

import os
import sys
import time
import re
import json
import sqlite3
import imaplib
import email
from email.header import decode_header
import random
import string
import threading
import queue
import ipaddress
import urllib.request
import zlib
import base64
from datetime import datetime

try:
    from flask import Flask, request, jsonify, Response, send_from_directory, render_template_string
except ImportError:
    import subprocess
    print("Flask is not installed. Installing flask...", flush=True)
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "flask", "--quiet"])
    except Exception:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "flask", "--break-system-packages", "--quiet"])
    from flask import Flask, request, jsonify, Response, send_from_directory, render_template_string

# Cấu hình UTF-8 cho console
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

import secrets
import hmac

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "tempmail_public")
DB_PATH = os.path.join(BASE_DIR, "messages.db")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

def load_server_config():
    default_cfg = {
        "admin_key": "admin_hub_" + secrets.token_hex(6),
        "gmail_user": os.environ.get("GMAIL_USER", "phuckienviproaccklingaifreevip@gmail.com"),
        "gmail_pass": os.environ.get("GMAIL_PASS", "qtwxvnmzuyvxfzfa"),
        "target_domain": os.environ.get("TARGET_DOMAIN", "blueskyvinh.online"),
        "port": int(os.environ.get("PORT", 3000)),
        "max_mail_age_minutes": 45,
        "allow_vietnam_ip_only": False
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                saved = json.load(f)
                default_cfg.update(saved)
        except Exception:
            pass
    return default_cfg

SERVER_CONFIG = load_server_config()
CONFIG = SERVER_CONFIG
GMAIL_USER = SERVER_CONFIG["gmail_user"]
GMAIL_PASS = SERVER_CONFIG["gmail_pass"]
TARGET_DOMAIN = SERVER_CONFIG["target_domain"]
ADMIN_KEY = SERVER_CONFIG["admin_key"]
PORT = int(SERVER_CONFIG.get("port", 3000))

db_lock = threading.Lock()

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db_lock:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_uid TEXT UNIQUE,
                recipient TEXT NOT NULL,
                recipient_prefix TEXT NOT NULL,
                sender TEXT,
                sender_email TEXT,
                subject TEXT,
                date_str TEXT,
                timestamp INTEGER,
                otp TEXT,
                service_tag TEXT,
                body_text TEXT,
                body_html TEXT,
                verify_link TEXT,
                raw_headers TEXT,
                is_read INTEGER DEFAULT 0,
                created_at TEXT
            )
        """)
        cursor.execute("PRAGMA table_info(emails)")
        cols = [c[1] for c in cursor.fetchall()]
        if "verify_link" not in cols:
            cursor.execute("ALTER TABLE emails ADD COLUMN verify_link TEXT")

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_emails_recipient ON emails(recipient)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_emails_prefix ON emails(recipient_prefix)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_emails_timestamp ON emails(timestamp DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_emails_uid ON emails(msg_uid)")
        conn.commit()
        conn.close()

# ----------------------------------------------------------------------
# TIỆN ÍCH GIẢI MÃ TIÊU ĐỀ & NỘI DUNG EMAIL
# ----------------------------------------------------------------------
def decode_mime_words(val):
    if not val:
        return ""
    try:
        parts = decode_header(val)
        res = []
        for text, enc in parts:
            if isinstance(text, bytes):
                res.append(text.decode(enc or 'utf-8', errors='ignore'))
            else:
                res.append(str(text))
        return " ".join(res).strip()
    except Exception:
        return str(val)

def extract_recipient_address(msg):
    """
    Bóc tách chính xác địa chỉ đích @blueskyvinh.online:
    Kiểm tra To, X-Forwarded-For, Delivered-To, Received headers
    """
    # 1. Thử từ trường 'To'
    to_val = decode_mime_words(msg.get('To'))
    m = re.search(r'([\w\.\-\+]+@' + re.escape(TARGET_DOMAIN) + r')', to_val, re.I)
    if m:
        return m.group(1).lower().strip()

    # 2. Thử từ trường 'X-Forwarded-For'
    xff = str(msg.get('X-Forwarded-For', ''))
    m = re.search(r'([\w\.\-\+]+@' + re.escape(TARGET_DOMAIN) + r')', xff, re.I)
    if m:
        return m.group(1).lower().strip()

    # 3. Thử từ các trường 'Received'
    for rcv in msg.get_all('Received', []):
        m = re.search(r'for\s+<([\w\.\-\+]+@' + re.escape(TARGET_DOMAIN) + r')>', str(rcv), re.I)
        if m:
            return m.group(1).lower().strip()

    # 4. Thử quét toàn bộ các header khác
    for k, v in msg.items():
        if k.lower() not in ['return-path', 'received-spf', 'authentication-results', 'arc-authentication-results']:
            m = re.search(r'([\w\.\-\+]+@' + re.escape(TARGET_DOMAIN) + r')', str(v), re.I)
            if m:
                return m.group(1).lower().strip()

    # Fallback
    if to_val:
        m2 = re.search(r'[\w\.\-\+]+@[\w\.\-]+', to_val)
        if m2:
            return m2.group(0).lower().strip()
        return to_val.strip().lower()
    return f"unknown@{TARGET_DOMAIN}"

def extract_sender_email(from_str):
    if not from_str:
        return ""
    m = re.search(r'<([^>]+)>', from_str)
    if m:
        return m.group(1).strip()
    m2 = re.search(r'[\w\.\-\+]+@[\w\.\-]+', from_str)
    if m2:
        return m2.group(0).strip()
    return from_str.strip()

def detect_service_and_otp(subject, body, sender):
    """
    Bóc tách thông minh mã OTP từ nội dung thư (Meta, Facebook, Google, Discord, v.v.)
    """
    full_text = f"{subject or ''}\n{sender or ''}\n{body or ''}"
    service = "Khác"
    
    s_lower = full_text.lower()
    if "meta" in s_lower or "facebook" in s_lower:
        service = "Meta Platform"
    elif "google" in s_lower:
        service = "Google"
    elif "discord" in s_lower:
        service = "Discord"
    elif "microsoft" in s_lower or "outlook" in s_lower:
        service = "Microsoft"
    elif "telegram" in s_lower:
        service = "Telegram"
    elif "tiktok" in s_lower:
        service = "TikTok"
    elif "twitter" in s_lower or "x.com" in s_lower:
        service = "X / Twitter"
    elif "steam" in s_lower:
        service = "Steam"

    otp = None

    # Mẫu chuẩn Meta HTML (Thường nằm trong thẻ CSS style padding hoặc font lớn)
    m_meta = re.search(r'(?:padding:\s*16px|letter-spacing)[^>]*>\s*([0-9]{6})\s*<', body or '', re.I)
    if m_meta and m_meta.group(1).strip() != "141823":
        otp = m_meta.group(1).strip()

    # Mẫu Tiêu đề chứa mã (Ví dụ: "150674 is your Meta account login code", "Use code 207243 to log in")
    if not otp and subject:
        m_subj = re.search(r'^\s*([0-9]{4,8})\b', subject) or \
                 re.search(r'\b(?:code|mã)\s*([0-9]{4,8})\b', subject, re.I) or \
                 re.search(r'\b([0-9]{6})\b', subject)
        if m_subj and m_subj.group(1).strip() != "141823":
            otp = m_subj.group(1).strip()

    # Mẫu Google (G-123456)
    if not otp:
        m_g = re.search(r'\bG-([0-9]{6})\b', full_text, re.I)
        if m_g:
            otp = m_g.group(1).strip()

    # Mẫu chung kèm từ khóa
    if not otp:
        m_gen = re.search(r'(?:confirmation code|verification code|use code|security code|passcode|one-time code|mã xác minh|mã xác thực|mã otp|mã xác nhận)[\s\S]{0,45}?\b([0-9]{4,8})\b', full_text, re.I)
        if m_gen and m_gen.group(1).strip() not in ["141823", "000000"]:
            otp = m_gen.group(1).strip()

    # Mẫu 6 số độc lập trong thẻ HTML nổi bật
    if not otp and body:
        for cand in re.findall(r'>\s*([0-9]{6})\s*<', body):
            if cand.strip() not in ["141823", "000000"]:
                otp = cand.strip()
                break

    return service, otp

def extract_verification_link(body_html, body_text):
    """
    Trích xuất thông minh các đường link kích hoạt, xác thực tài khoản (Confirm, Verify, Activate)
    """
    if body_html:
        links = re.findall(r'href=[\'"](https?://[^\'">\s]+)[\'"]', body_html, re.I)
        for link in links:
            l_lower = link.lower()
            if any(k in l_lower for k in ['confirm', 'verify', 'verification', 'activate', 'validation', 'token', 'action']):
                if not any(k in l_lower for k in ['unsubscribe', 'privacy', 'terms', 'facebook.com/help', 'support', 'help.', 'instagram.com/legal']):
                    return link
    if body_text:
        links = re.findall(r'(https?://[^\s<>"]+)', body_text)
        for link in links:
            l_lower = link.lower()
            if any(k in l_lower for k in ['confirm', 'verify', 'activate', 'validation']):
                if not any(k in l_lower for k in ['unsubscribe', 'privacy', 'terms', 'help']):
                    return link
    return None

# ----------------------------------------------------------------------
# IMAP BACKGROUND SYNC WORKER
# ----------------------------------------------------------------------
class IMAPSyncWorker(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True
        self.status = "Đang khởi tạo..."
        self.is_connected = False
        self.last_sync_time = None
        self.last_seq_count = 0
        self.total_fetched = 0
        self.listeners = set() # Set of queues for SSE
        self.lock = threading.Lock()

    def add_listener(self, q):
        with self.lock:
            self.listeners.add(q)

    def remove_listener(self, q):
        with self.lock:
            self.listeners.discard(q)

    def broadcast_new_email(self, email_data):
        with self.lock:
            for q in list(self.listeners):
                try:
                    q.put_nowait(email_data)
                except Exception:
                    pass

    def run(self):
        print(f"🚀 [IMAP Worker] Bắt đầu tiến trình đồng bộ Gmail: {GMAIL_USER}", flush=True)
        init_db()

        while self.running:
            mail = None
            try:
                self.status = "Đang kết nối Gmail IMAP..."
                mail = imaplib.IMAP4_SSL("imap.gmail.com", 993, timeout=60)
                mail.login(GMAIL_USER, GMAIL_PASS)
                self.is_connected = True
                self.status = "Đã kết nối thành công"

                # Lấy số lượng email trong INBOX
                st, cnt_data = mail.select("INBOX", readonly=True)
                if st != "OK":
                    raise Exception(f"Không thể chọn INBOX: {cnt_data}")
                
                total_inbox = int(cnt_data[0])
                print(f"📬 [IMAP Worker] INBOX hiện có {total_inbox} thư.", flush=True)

                # Kiểm tra trong DB xem đã có bao nhiêu thư
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM emails")
                db_count = cursor.fetchone()[0]
                conn.close()

                # Nếu DB trống hoặc mới bật lần đầu, quét 5 thư gần nhất để nạp dữ liệu nhẹ nhàng
                if db_count == 0:
                    start_fetch = max(1, total_inbox - 5)
                    print(f"🔄 [IMAP Worker] Nạp ban đầu 5 thư gần nhất ({start_fetch}:{total_inbox})...", flush=True)
                    self._fetch_range(mail, start_fetch, total_inbox)
                
                self.last_seq_count = total_inbox
                self.last_sync_time = datetime.now().strftime("%H:%M:%S %d/%m/%Y")
                self.status = "Đang lắng nghe thư mới..."

                # Vòng lặp kiểm tra thư mới siêu nhanh (mỗi 3 giây)
                while self.running:
                    time.sleep(3.0)
                    try:
                        st, cnt_data = mail.select("INBOX", readonly=True)
                        if st == "OK" and cnt_data and cnt_data[0]:
                            current_total = int(cnt_data[0])
                            self.last_sync_time = datetime.now().strftime("%H:%M:%S %d/%m/%Y")
                            
                            if current_total > self.last_seq_count:
                                new_start = self.last_seq_count + 1
                                print(f"✨ [IMAP Worker] Phát hiện {current_total - self.last_seq_count} thư mới! Đang nạp ({new_start}:{current_total})...", flush=True)
                                self._fetch_range(mail, new_start, current_total)
                                self.last_seq_count = current_total
                            elif current_total < self.last_seq_count:
                                # Hòm thư có thể bị xóa bớt thư
                                self.last_seq_count = current_total
                    except (imaplib.IMAP4.abort, imaplib.IMAP4.error, OSError) as e:
                        print(f"⚠️ [IMAP Worker] Kết nối chập chờn: {e}, đang kết nối lại...", flush=True)
                        break

            except Exception as e:
                self.is_connected = False
                self.status = f"Lỗi kết nối: {str(e)[:50]}"
                print(f"❌ [IMAP Worker] Ngoại lệ: {e}", flush=True)
                time.sleep(4)
            finally:
                if mail:
                    try:
                        mail.logout()
                    except Exception:
                        pass

    def _fetch_range(self, mail, start_idx, end_idx):
        if start_idx > end_idx:
            return
        try:
            st, data = mail.fetch(f"{start_idx}:{end_idx}", "(RFC822)")
            if st != "OK" or not data:
                return

            new_inserted = []
            conn = get_db()
            cursor = conn.cursor()

            for item in data:
                if not isinstance(item, tuple) or len(item) < 2:
                    continue
                raw_bytes = item[1]
                msg = email.message_from_bytes(raw_bytes)

                recipient = extract_recipient_address(msg)
                recipient_prefix = recipient.split("@")[0].lower() if "@" in recipient else recipient.lower()

                # Kiểm tra lọc: Chấp nhận mọi thư gửi về @blueskyvinh.online
                # hoặc nếu đang nạp ban đầu thì nạp các thư liên quan tới domain
                is_target = TARGET_DOMAIN in recipient.lower()
                if not is_target:
                    # Kiểm tra xem có header nào nhắc tới blueskyvinh.online không
                    all_h = str(msg)
                    if TARGET_DOMAIN not in all_h.lower():
                        continue

                # Tạo UID duy nhất từ Message-ID hoặc hash
                msg_id_header = msg.get("Message-ID", "")
                if msg_id_header:
                    msg_uid = msg_id_header.strip("<>")
                else:
                    msg_uid = f"msg_{hash(raw_bytes)}_{len(raw_bytes)}"

                subject = decode_mime_words(msg.get("Subject", "(Không có tiêu đề)"))
                from_raw = decode_mime_words(msg.get("From", ""))
                sender_email = extract_sender_email(from_raw)
                date_raw = decode_mime_words(msg.get("Date", ""))

                # Trích xuất body HTML và Plain text
                body_text = ""
                body_html = ""
                for part in msg.walk():
                    content_type = part.get_content_type()
                    charset = part.get_content_charset() or "utf-8"
                    if content_type == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text += payload.decode(charset, errors="ignore")
                    elif content_type == "text/html":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_html += payload.decode(charset, errors="ignore")

                # Nếu chỉ có plain text mà không có html, tự tạo html cơ bản
                if not body_html and body_text:
                    body_html = f"<div style='font-family:sans-serif;white-space:pre-wrap;'>{body_text}</div>"

                # Bóc tách Service & OTP & Link xác minh / kích hoạt
                service, otp = detect_service_and_otp(subject, body_html or body_text, from_raw)
                verify_link = extract_verification_link(body_html, body_text)

                # Tính timestamp
                timestamp = int(time.time())
                try:
                    parsed_date = email.utils.parsedate_to_datetime(date_raw)
                    if parsed_date:
                        timestamp = int(parsed_date.timestamp())
                except Exception:
                    pass

                # Lưu vào DB
                with db_lock:
                    try:
                        cursor.execute("""
                            INSERT OR IGNORE INTO emails (
                                msg_uid, recipient, recipient_prefix, sender, sender_email,
                                subject, date_str, timestamp, otp, service_tag,
                                body_text, body_html, verify_link, raw_headers, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            msg_uid, recipient, recipient_prefix, from_raw, sender_email,
                            subject, date_raw, timestamp, otp, service,
                            body_text, body_html, verify_link, "", datetime.now().isoformat()
                        ))
                        if cursor.rowcount > 0:
                            email_id = cursor.lastrowid
                            inserted_item = {
                                "id": email_id,
                                "msg_uid": msg_uid,
                                "recipient": recipient,
                                "recipient_prefix": recipient_prefix,
                                "sender": from_raw,
                                "sender_email": sender_email,
                                "subject": subject,
                                "date_str": date_raw,
                                "timestamp": timestamp,
                                "otp": otp,
                                "service_tag": service,
                                "verify_link": verify_link,
                                "has_html": bool(body_html),
                                "preview": (body_text or "")[:150].strip()
                            }
                            new_inserted.append(inserted_item)
                    except Exception as ex:
                        print(f"Lỗi chèn email: {ex}", flush=True)

            conn.commit()
            conn.close()

            if new_inserted:
                print(f"📥 [IMAP Worker] Đã lưu thành công {len(new_inserted)} thư mới vào cơ sở dữ liệu!", flush=True)
                for item in new_inserted:
                    if item.get("otp"):
                        print(f"🔑 [MÃ OTP PHÁT HIỆN]: [{item['otp']}] cho [{item['recipient']}] từ [{item['service_tag']}]", flush=True)
                    self.broadcast_new_email(item)

        except Exception as e:
            print(f"❌ [IMAP Worker] Lỗi tải thư: {e}", flush=True)

# Khởi tạo background worker
imap_worker = IMAPSyncWorker()
imap_worker.start()

# ----------------------------------------------------------------------
# AUTO-PURGE WORKER: TỰ ĐỘNG DỌN DẸP THƯ CŨ ĐỂ BẢO MẬT & GIẢI PHÓNG BỘ NHỚ
# ----------------------------------------------------------------------
class AutoPurgeWorker(threading.Thread):
    def __init__(self, interval_sec=180, max_age_sec=2700):
        super().__init__(daemon=True)
        self.interval_sec = interval_sec  # Kiểm tra mỗi 3 phút
        self.max_age_sec = max_age_sec    # Xóa thư cũ hơn 45 phút
        self.running = True

    def run(self):
        print(f"🧹 [Auto-Purge] Bật tiến trình tự động dọn rác (xóa thư cũ hơn {self.max_age_sec//60} phút mỗi {self.interval_sec}s)", flush=True)
        while self.running:
            time.sleep(self.interval_sec)
            try:
                cutoff = int(time.time()) - self.max_age_sec
                with db_lock:
                    conn = get_db()
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM emails WHERE timestamp < ?", (cutoff,))
                    deleted = cursor.rowcount
                    conn.commit()
                    conn.close()
                if deleted > 0:
                    print(f"🧹 [Auto-Purge] Đã dọn sạch {deleted} email cũ để bảo vệ quyền riêng tư & giải phóng ổ cứng.", flush=True)
            except Exception as e:
                print(f"⚠️ [Auto-Purge] Lỗi dọn rác: {e}", flush=True)

auto_purge_worker = AutoPurgeWorker()
auto_purge_worker.start()

# ----------------------------------------------------------------------
# RATE LIMITING ENGINE (CHỐNG SPAM & DDOS THEO IP)
# ----------------------------------------------------------------------
rate_limit_lock = threading.Lock()
ip_request_history = {} # (ip, action) -> list of timestamps
geo_cache_lock = threading.Lock()
ip_country_cache = {} # ip -> (country_code, timestamp)

def get_client_ip():
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip and cf_ip.strip():
        return cf_ip.strip()
    x_real_ip = request.headers.get("X-Real-IP")
    if x_real_ip and x_real_ip.strip():
        return x_real_ip.strip()
    xff = request.headers.get("X-Forwarded-For")
    if xff and xff.strip():
        return xff.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

def is_private_or_local_ip(ip_str):
    if not ip_str:
        return True
    clean_ip = ip_str.split(":")[0].strip()
    if clean_ip in ["localhost", "127.0.0.1", "::1"]:
        return True
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except Exception:
        return False

def get_ip_country(ip_str):
    # 1. Cloudflare Country Header (Tức thì và chính xác 100% khi chạy qua Cloudflare)
    cf_country = request.headers.get("CF-IPCountry")
    if cf_country and cf_country.strip() and cf_country.strip().upper() != "XX":
        return cf_country.strip().upper()

    # 2. Localhost / Mạng nội bộ -> Coi như VN để cho phép dev, test và sử dụng máy chủ
    if is_private_or_local_ip(ip_str):
        return "VN"

    # 3. Tra cứu từ bộ nhớ cache
    now = time.time()
    with geo_cache_lock:
        if ip_str in ip_country_cache:
            code, ts = ip_country_cache[ip_str]
            if now - ts < 86400: # Cache 24 giờ
                return code

    # 4. Tra cứu GeoIP trực tuyến từ ip-api.com
    try:
        url = f"http://ip-api.com/json/{ip_str}?fields=status,countryCode"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                code = data.get("countryCode", "UNKNOWN").upper()
                with geo_cache_lock:
                    ip_country_cache[ip_str] = (code, now)
                return code
    except Exception:
        pass

    # Dự phòng ipwho.is
    try:
        url = f"https://ipwho.is/{ip_str}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            code = (data.get("country_code") or "UNKNOWN").upper()
            with geo_cache_lock:
                ip_country_cache[ip_str] = (code, now)
            return code
    except Exception:
        pass

    return "UNKNOWN"

def check_rate_limit(action="default", limit=30, window_sec=60):
    ip = get_client_ip()
    key = (ip, action)
    now = time.time()
    with rate_limit_lock:
        if key not in ip_request_history:
            ip_request_history[key] = []
        ip_request_history[key] = [t for t in ip_request_history[key] if now - t < window_sec]
        if len(ip_request_history[key]) >= limit:
            return False, ip
        ip_request_history[key].append(now)
        return True, ip

def is_admin_authorized():
    key = request.headers.get("X-Admin-Key") or request.args.get("key") or request.args.get("admin_key")
    if not key:
        return False
    return hmac.compare_digest(str(key).strip(), str(ADMIN_KEY).strip())

# ----------------------------------------------------------------------
# FLASK WEB APPLICATION & REST APIS
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# EMBEDDED DASHBOARD FRONTEND (HTML + CSS + JS)
# ----------------------------------------------------------------------
EMBEDDED_HTML_B64 = """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"""
EMBEDDED_INDEX_HTML = zlib.decompress(base64.b64decode(EMBEDDED_HTML_B64)).decode("utf-8")

app = Flask(__name__)

# BẢO VỆ CHỈ CHO PHÉP IP VIỆT NAM (VN) TRUY CẬP
@app.before_request
def enforce_vietnam_ip_only():
    # Bỏ qua nếu tắt trong config
    if not CONFIG.get("allow_vietnam_ip_only", True):
        return

    client_ip = get_client_ip()

    # Admin key có thể bypass
    if is_admin_authorized():
        return

    country = get_ip_country(client_ip)
    if country != "VN":
        print(f"⛔ [Chặn IP Ngoại] Từ chối IP: {client_ip} (Quốc gia: {country}) truy cập {request.path}", flush=True)
        if request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "error": f"403 Forbidden: Hệ thống chỉ phục vụ người dùng có IP tại Việt Nam (Phát hiện: {country}). Truy cập bị từ chối.",
                "country": country,
                "client_ip": client_ip
            }), 403
        else:
            blocked_html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>403 Forbidden - Chỉ Hỗ Trợ IP Việt Nam</title>
  <style>
    body {{ background: #070d19; color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 20px; text-align: center; }}
    .card {{ background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 16px; padding: 40px 30px; max-width: 520px; box-shadow: 0 0 40px rgba(239, 68, 68, 0.25); }}
    h1 {{ color: #ef4444; font-size: 1.8rem; margin: 0 0 12px 0; }}
    p {{ color: #94a3b8; font-size: 0.95rem; line-height: 1.6; margin: 0 0 20px 0; }}
    .meta-box {{ background: rgba(0,0,0,0.5); border-radius: 8px; padding: 12px; font-family: monospace; font-size: 0.88rem; color: #38bdf8; margin-bottom: 20px; border: 1px solid rgba(255,255,255,0.08); }}
    .badge {{ display: inline-block; background: #dc2626; color: #fff; padding: 4px 14px; border-radius: 20px; font-weight: 700; font-size: 0.8rem; letter-spacing: 0.5px; margin-bottom: 12px; }}
  </style>
</head>
<body>
  <div class="card">
    <div style="font-size: 3.2rem; margin-bottom: 10px;">🚫</div>
    <span class="badge">403 ACCESS DENIED</span>
    <h1>TRUY CẬP BỊ TỪ CHỐI</h1>
    <p>Hệ thống Temp Mail <strong>@blueskyvinh.online</strong> chỉ phục vụ người dùng có địa chỉ IP tại <strong>Việt Nam (VN)</strong> nhằm ngăn chặn các yêu cầu không hợp lệ.</p>
    <div class="meta-box">
      IP của bạn: <strong>{client_ip}</strong><br>
      Quốc gia nhận diện: <strong style="color:#ef4444;">{country}</strong>
    </div>
    <p style="font-size:0.8rem; color:#64748b; margin:0;">Nếu đang bật VPN / Proxy nước ngoài, vui lòng tắt hoặc chuyển sang IP Việt Nam để truy cập.</p>
  </div>
</body>
</html>"""
            return Response(blocked_html, status=403, mimetype="text/html; charset=utf-8")

FIRST_NAMES = ["alex", "emma", "david", "sophia", "james", "olivia", "john", "emily", "michael", "sarah", "daniel", "mia", "william", "clara", "noah", "grace", "kyle", "zoey"]
LAST_NAMES = ["smith", "johnson", "williams", "brown", "jones", "miller", "davis", "wilson", "anderson", "taylor", "thomas", "moore", "jackson", "martin", "lee", "clark"]

@app.route("/")
def index():
    return Response(EMBEDDED_INDEX_HTML, mimetype="text/html; charset=utf-8")

@app.route("/style.css")
def serve_css():
    return Response("", mimetype="text/css")

@app.route("/app.js")
def serve_js():
    return Response("", mimetype="application/javascript")

# API: Trạng thái hệ thống (BẢO MẬT: Tuyệt đối KHÔNG lộ Gmail nguồn hoặc thống kê nhạy cảm)
@app.route("/api/status", methods=["GET"])
def api_status():
    return jsonify({
        "status": "online",
        "domain": TARGET_DOMAIN,
        "imap_connected": imap_worker.is_connected,
        "server_time": datetime.now().strftime("%H:%M:%S %d/%m/%Y")
    })

# API: Xác thực mật khẩu Admin bí mật
@app.route("/api/admin/verify", methods=["POST"])
def api_admin_verify():
    data = request.get_json(silent=True) or {}
    key = data.get("password") or data.get("key") or ""
    if hmac.compare_digest(str(key).strip(), str(ADMIN_KEY).strip()):
        return jsonify({"success": True, "token": ADMIN_KEY})
    return jsonify({"success": False, "error": "Mật khẩu Admin bí mật không chính xác!"}), 401

# API: Sinh địa chỉ email ngẫu nhiên hợp lệ (Giới hạn tối đa 50 mail cho mỗi IP)
@app.route("/api/generate", methods=["GET", "POST"])
def api_generate():
    limit_generate = int(CONFIG.get("rate_limit_generate_per_ip", 50))
    window_sec = int(CONFIG.get("rate_limit_generate_window_sec", 3600))
    allowed, ip = check_rate_limit(action="generate_mail", limit=limit_generate, window_sec=window_sec)
    if not allowed:
        return jsonify({
            "success": False,
            "error": f"Địa chỉ IP ({ip}) của bạn đã đạt giới hạn tối đa {limit_generate} mail! Vui lòng chờ để tiếp tục tạo thư."
        }), 429

    mode = request.args.get("mode", "human").strip().lower()
    if mode == "short":
        chars = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        prefix = f"bsk_{chars}"
    else:
        fname = random.choice(FIRST_NAMES)
        lname = random.choice(LAST_NAMES)
        year = random.randint(1994, 2004)
        rand_num = random.randint(10, 99)
        prefix = f"{fname}{lname}{year}{rand_num}"

    email_addr = f"{prefix}@{TARGET_DOMAIN}"
    return jsonify({
        "success": True,
        "email": email_addr,
        "prefix": prefix,
        "mode": mode,
        "domain": TARGET_DOMAIN
    })

# API: Lấy danh sách thư cho một mailbox cụ thể (Lọc since & Rate limit 60 req/min)
@app.route("/api/mailbox/<path:recipient>", methods=["GET"])
def api_get_mailbox(recipient):
    allowed, ip = check_rate_limit(action="fetch_mailbox", limit=60, window_sec=60)
    if not allowed:
        return jsonify({"success": False, "error": "Tần suất kiểm tra thư quá nhanh! Vui lòng chờ vài giây."}), 429

    clean_target = recipient.lower().strip()
    prefix = clean_target.split("@")[0]
    
    # Mặc định lấy từ trước 30 phút đến thời gian thực nếu không truyền since
    default_since = int(time.time()) - 1800
    since_ts = request.args.get("since", default=default_since, type=int)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, msg_uid, recipient, recipient_prefix, sender, sender_email,
               subject, date_str, timestamp, otp, service_tag, verify_link,
               SUBSTR(body_text, 1, 180) as preview,
               (body_html IS NOT NULL AND LENGTH(body_html) > 0) as has_html,
               is_read, created_at
        FROM emails
        WHERE (recipient = ? OR recipient_prefix = ?) AND timestamp >= ?
        ORDER BY timestamp DESC, id DESC
    """, (clean_target, prefix, since_ts))
    rows = cursor.fetchall()
    conn.close()

    emails = [dict(row) for row in rows]
    return jsonify({
        "success": True,
        "recipient": clean_target,
        "since": since_ts,
        "count": len(emails),
        "emails": emails
    })

# API: Lấy mã OTP mới nhất cho một email (Lọc từ mốc thời gian since)
@app.route("/api/mailbox/<path:recipient>/otp", methods=["GET"])
def api_get_mailbox_otp(recipient):
    clean_target = recipient.lower().strip()
    prefix = clean_target.split("@")[0]
    
    default_since = int(time.time()) - 1800
    since_ts = request.args.get("since", default=default_since, type=int)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, recipient, sender, subject, otp, service_tag, verify_link, date_str, timestamp
        FROM emails
        WHERE (recipient = ? OR recipient_prefix = ?) 
          AND otp IS NOT NULL AND LENGTH(otp) > 0
          AND timestamp >= ?
        ORDER BY timestamp DESC, id DESC
        LIMIT 1
    """, (clean_target, prefix, since_ts))
    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify({
            "success": True,
            "has_otp": True,
            "otp": row["otp"],
            "recipient": row["recipient"],
            "sender": row["sender"],
            "subject": row["subject"],
            "service_tag": row["service_tag"],
            "verify_link": row["verify_link"],
            "date": row["date_str"],
            "timestamp": row["timestamp"]
        })
    else:
        return jsonify({
            "success": True,
            "has_otp": False,
            "otp": None,
            "recipient": clean_target,
            "message": "Chưa nhận được mã OTP nào trong khoảng thời gian hợp lệ"
        })

# API: Lấy danh sách toàn bộ thư (ĐÃ KHÓA BẢO MẬT: CHỈ ADMIN MỚI ĐƯỢC PHÉP TRUY CẬP)
@app.route("/api/messages", methods=["GET"])
def api_messages():
    if not is_admin_authorized():
        return jsonify({
            "success": False,
            "error": "403 Forbidden: Endpoint xem toàn bộ hòm thư domain đã bị khóa để bảo vệ mã OTP của người dùng. Vui lòng cung cấp Admin Key."
        }), 403

    limit = min(int(request.args.get("limit", 60)), 200)
    search = request.args.get("search", "").strip().lower()

    conn = get_db()
    cursor = conn.cursor()

    if search:
        cursor.execute("""
            SELECT id, msg_uid, recipient, recipient_prefix, sender, sender_email,
                   subject, date_str, timestamp, otp, service_tag, verify_link,
                   SUBSTR(body_text, 1, 180) as preview,
                   (body_html IS NOT NULL AND LENGTH(body_html) > 0) as has_html,
                   is_read, created_at
            FROM emails
            WHERE recipient LIKE ? OR subject LIKE ? OR sender LIKE ? OR otp LIKE ?
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
        """, (f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%", limit))
    else:
        cursor.execute("""
            SELECT id, msg_uid, recipient, recipient_prefix, sender, sender_email,
               subject, date_str, timestamp, otp, service_tag, verify_link,
               SUBSTR(body_text, 1, 180) as preview,
               (body_html IS NOT NULL AND LENGTH(body_html) > 0) as has_html,
               is_read, created_at
            FROM emails
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
        """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    emails = [dict(row) for row in rows]
    return jsonify({
        "success": True,
        "count": len(emails),
        "emails": emails
    })

# API: Thống kê chi tiết hệ thống cho Admin
@app.route("/api/admin/stats", methods=["GET"])
def api_admin_stats():
    if not is_admin_authorized():
        return jsonify({"success": False, "error": "403 Forbidden: Yêu cầu quyền Admin."}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM emails")
    total_emails = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(DISTINCT recipient) FROM emails")
    total_recipients = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM emails WHERE otp IS NOT NULL AND LENGTH(otp) > 0")
    total_otps = cursor.fetchone()[0]
    cursor.execute("SELECT service_tag, COUNT(*) as cnt FROM emails GROUP BY service_tag ORDER BY cnt DESC")
    service_breakdown = [dict(r) for r in cursor.fetchall()]
    conn.close()

    db_size_mb = 0
    if os.path.exists(DB_PATH):
        db_size_mb = round(os.path.getsize(DB_PATH) / (1024 * 1024), 2)

    return jsonify({
        "success": True,
        "total_emails": total_emails,
        "total_recipients": total_recipients,
        "total_otps": total_otps,
        "service_breakdown": service_breakdown,
        "db_size_mb": db_size_mb,
        "imap_status": imap_worker.status,
        "last_sync": imap_worker.last_sync_time
    })

# API: Admin dọn rác thủ công ngay lập tức
@app.route("/api/admin/purge_now", methods=["POST"])
def api_admin_purge_now():
    if not is_admin_authorized():
        return jsonify({"success": False, "error": "403 Forbidden: Yêu cầu quyền Admin."}), 403

    data = request.get_json(silent=True) or {}
    minutes = int(data.get("minutes", 30))
    cutoff = int(time.time()) - (minutes * 60)

    with db_lock:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM emails WHERE timestamp < ?", (cutoff,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()

    return jsonify({
        "success": True,
        "deleted_count": deleted,
        "message": f"Đã xóa vĩnh viễn {deleted} email cũ hơn {minutes} phút khỏi hệ thống!"
    })

# API: Lấy chi tiết 1 email (BẢO MẬT: Chỉ chủ hòm thư hoặc Admin mới được xem)
@app.route("/api/message/<int:msg_id>", methods=["GET"])
def api_message_detail(msg_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM emails WHERE id = ?", (msg_id,))
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        return jsonify({"success": False, "error": "Không tìm thấy thư"}), 404

    # Kiểm tra quyền: nếu không phải Admin thì phải gửi đúng ?email= khớp với recipient
    req_email = request.args.get("email", "").strip().lower()
    rec_lower = (row["recipient"] or "").lower()
    rec_prefix = (row["recipient_prefix"] or "").lower()
    if not is_admin_authorized():
        if not req_email or (req_email != rec_lower and req_email != rec_prefix and not rec_lower.startswith(req_email.split("@")[0] + "@")):
            conn.close()
            return jsonify({"success": False, "error": "403 Forbidden: Bạn không có quyền truy cập email này."}), 403

    # Đánh dấu đã đọc
    cursor.execute("UPDATE emails SET is_read = 1 WHERE id = ?", (msg_id,))
    conn.commit()
    conn.close()

    data = dict(row)
    return jsonify({"success": True, "email": data})

# API: Trả về trực tiếp nội dung HTML để iframe render (BẢO MẬT: Kiểm tra quyền sở hữu)
@app.route("/api/message/<int:msg_id>/html", methods=["GET"])
def api_message_html(msg_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT recipient, recipient_prefix, body_html, body_text, subject FROM emails WHERE id = ?", (msg_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return "<h3>Không tìm thấy email</h3>", 404

    # Kiểm tra quyền sở hữu
    req_email = request.args.get("email", "").strip().lower()
    rec_lower = (row["recipient"] or "").lower()
    rec_prefix = (row["recipient_prefix"] or "").lower()
    if not is_admin_authorized():
        if not req_email or (req_email != rec_lower and req_email != rec_prefix and not rec_lower.startswith(req_email.split("@")[0] + "@")):
            return "<h3>403 Forbidden: Bạn không có quyền xem nội dung thư này</h3>", 403

    html_content = row["body_html"]
    if not html_content:
        # Chuyển text plain thành HTML an toàn
        text = row["body_text"] or "(Không có nội dung)"
        html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset='utf-8'>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px; line-height: 1.6; color: #1e293b; background: #fff; }}
    pre {{ white-space: pre-wrap; font-family: inherit; }}
  </style>
</head>
<body><pre>{text}</pre></body></html>"""

    # Inject base tag và target _blank cho mọi liên kết
    if "<head>" in html_content:
        html_content = html_content.replace("<head>", "<head><base target='_blank'>", 1)
    else:
        html_content = f"<base target='_blank'>" + html_content

    return Response(html_content, mimetype="text/html; charset=utf-8")

# API: Lấy danh sách các hòm thư đã nhận mail (KHÓA CHẶT: CHỈ ADMIN MỚI ĐƯỢC XEM)
@app.route("/api/mailboxes", methods=["GET"])
def api_mailboxes():
    if not is_admin_authorized():
        return jsonify({"success": False, "error": "403 Forbidden: Yêu cầu quyền Admin để xem danh sách hòm thư."}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT recipient, COUNT(*) as mail_count, MAX(timestamp) as last_active,
               MAX(otp) as latest_otp
        FROM emails
        GROUP BY recipient
        ORDER BY last_active DESC
        LIMIT 100
    """)
    rows = cursor.fetchall()
    conn.close()
    return jsonify({"success": True, "mailboxes": [dict(r) for r in rows]})

# API: Xóa toàn bộ thư của 1 mailbox
@app.route("/api/mailbox/<path:recipient>", methods=["DELETE"])
def api_delete_mailbox(recipient):
    clean_target = recipient.lower().strip()
    prefix = clean_target.split("@")[0]

    with db_lock:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM emails WHERE recipient = ? OR recipient_prefix = ?", (clean_target, prefix))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()

    return jsonify({"success": True, "deleted_count": deleted})

# API: Xóa 1 thư
@app.route("/api/message/<int:msg_id>", methods=["DELETE"])
def api_delete_message(msg_id):
    with db_lock:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM emails WHERE id = ?", (msg_id,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
    return jsonify({"success": True, "deleted": deleted > 0})

# API: Kích hoạt đồng bộ thủ công ngay lập tức
@app.route("/api/sync", methods=["POST"])
def api_manual_sync():
    # IMAP worker đang chạy vòng lặp 3s, trả về thông tin trạng thái
    return jsonify({
        "success": True,
        "message": "Tiến trình đồng bộ tự động đang hoạt động (chu kỳ 3 giây)",
        "last_sync": imap_worker.last_sync_time,
        "status": imap_worker.status
    })

# API: Server-Sent Events (SSE) để đẩy thư mới thời gian thực (BẢO MẬT: CHỈ PUSH THƯ CHO ĐÚNG CHỦ HÒM THƯ HOẶC ADMIN)
@app.route("/api/events")
def api_events():
    req_email = request.args.get("email", "").strip().lower()
    req_prefix = req_email.split("@")[0] if req_email else ""
    is_admin = is_admin_authorized()

    def event_stream():
        q = queue.Queue()
        imap_worker.add_listener(q)
        try:
            # Gửi ping kết nối ban đầu
            yield f"data: {json.dumps({'type': 'connected', 'time': time.time()})}\n\n"
            while True:
                try:
                    # Chờ thư mới tối đa 20 giây để gửi heartbeat keep-alive
                    item = q.get(timeout=20.0)
                    if is_admin:
                        yield f"data: {json.dumps({'type': 'new_email', 'data': item})}\n\n"
                    elif req_email:
                        item_rec = (item.get("recipient") or "").lower()
                        item_pref = (item.get("recipient_prefix") or "").lower()
                        if item_rec == req_email or item_pref == req_prefix or item_rec.startswith(req_prefix + "@"):
                            yield f"data: {json.dumps({'type': 'new_email', 'data': item})}\n\n"
                except queue.Empty:
                    # Gửi heartbeat
                    yield f": heartbeat {time.time()}\n\n"
        finally:
            imap_worker.remove_listener(q)

    return Response(event_stream(), mimetype="text/event-stream")

# ----------------------------------------------------------------------
# ENTRY POINT
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print(f"""
╔════════════════════════════════════════════════════════════════════════╗
║             🌟 NOTIFICATION DASHBOARD & MESSAGE HUB 🌟                 ║
╠════════════════════════════════════════════════════════════════════════╣
║  🌐 Web URL:      http://localhost:{PORT}                              ║
║  🎯 Domain:       @{TARGET_DOMAIN}                                     ║
║  🔑 Admin Key:    {ADMIN_KEY}                                          ║
║  📁 Config File:  config.json                                          ║
╚════════════════════════════════════════════════════════════════════════╝
    """, flush=True)

    app.run(host="0.0.0.0", port=PORT, threaded=True, debug=False)
