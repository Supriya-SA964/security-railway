from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS
from database import (init_db, save_user, verify_user, get_user,
                      get_all_users, get_verified_phones,
                      save_intruder, get_all_intruders, ADMIN_PHONE)
import os, random, re
from datetime import datetime
from twilio.rest import Client
from functools import wraps

app = Flask(__name__)
CORS(app)
init_db()

# ── Config — all from Railway environment variables ────────────────────
TWILIO_SID        = os.environ.get("TWILIO_SID",        "")
TWILIO_TOKEN      = os.environ.get("TWILIO_TOKEN",      "")
TWILIO_NUMBER     = os.environ.get("TWILIO_NUMBER",     "")
TWILIO_VERIFY_SID = os.environ.get("TWILIO_VERIFY_SID", "")
NGROK_URL         = os.environ.get("NGROK_URL",         "")

twilio_client = Client(TWILIO_SID, TWILIO_TOKEN)

print(f"[CONFIG] Admin       : {ADMIN_PHONE}")
print(f"[CONFIG] Twilio No   : {TWILIO_NUMBER}")
print(f"[CONFIG] Verify SID  : {TWILIO_VERIFY_SID[:10]}...")

# ══════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════

def clean_phone(phone):
    phone = phone.strip().replace(" ", "").replace("-", "")
    if phone.startswith("+"): return phone
    if phone.startswith("91") and len(phone) == 12: return "+" + phone
    if len(phone) == 10: return "+91" + phone
    return "+" + phone

def get_phone_from_request():
    phone = request.headers.get("X-Phone", "").strip()
    if phone: return clean_phone(phone)
    return None

def require_verified(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        phone = get_phone_from_request()
        if not phone:
            return jsonify({"error": "X-Phone header required"}), 401
        user = get_user(phone)
        if not user:
            return jsonify({"error": "User not found. Please register."}), 404
        if not user["verified"]:
            return jsonify({"error": "Phone not verified."}), 403
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        phone = get_phone_from_request()
        if not phone:
            return jsonify({"error": "X-Phone header required"}), 401
        user = get_user(phone)
        if not user or not user["verified"] or user["role"] != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated

@app.after_request
def add_headers(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Phone"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

# ══════════════════════════════════════════════════════
#  PUBLIC ROUTES
# ══════════════════════════════════════════════════════

@app.route("/")
def home():
    return jsonify({
        "status":  "online",
        "message": "AI Security System API",
        "version": "2.0"
    }), 200

@app.route("/ping")
def ping():
    return jsonify({"status": "online"}), 200

# ── Register ───────────────────────────────────────────────────────────
@app.route("/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data  = request.json or {}
    name  = data.get("name",  "").strip()
    phone = clean_phone(data.get("phone", "").strip())

    if not name:
        return jsonify({"error": "Name is required"}), 400
    if not re.match(r"^\+\d{10,15}$", phone):
        return jsonify({"error": "Invalid phone. Use +91XXXXXXXXXX"}), 400

    # Generate OTP for fallback method
    otp = str(random.randint(100000, 999999))
    save_user(name, phone, otp)

    # Try Twilio Verify first — works for ALL numbers
    try:
        twilio_client.verify.v2 \
            .services(TWILIO_VERIFY_SID) \
            .verifications \
            .create(to=phone, channel="sms")
        print(f"[REGISTER] Verify OTP sent to {phone}")
        return jsonify({
            "status":  "otp_sent",
            "message": f"OTP sent to {phone}",
            "phone":   phone,
            "method":  "verify"
        }), 200
    except Exception as e1:
        print(f"[REGISTER] Verify failed: {e1}")

    # Fallback — direct Twilio SMS
    try:
        twilio_client.messages.create(
            body=(
                f"Hi {name}!\n"
                f"Your Security App OTP: {otp}\n"
                f"Do not share this with anyone."
            ),
            from_=TWILIO_NUMBER,
            to=phone
        )
        print(f"[REGISTER] Direct OTP sent to {phone}")
        return jsonify({
            "status":  "otp_sent",
            "message": f"OTP sent to {phone}",
            "phone":   phone,
            "method":  "direct"
        }), 200
    except Exception as e2:
        print(f"[REGISTER] Both failed: {e2}")
        return jsonify({"error": str(e2)}), 500

# ── Verify OTP ─────────────────────────────────────────────────────────
@app.route("/verify-otp", methods=["POST", "OPTIONS"])
def verify_otp():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data  = request.json or {}
    phone = clean_phone(data.get("phone", ""))
    otp   = data.get("otp", "").strip()

    if len(otp) != 6:
        return jsonify({"error": "Enter 6 digit OTP"}), 400

    # Try Twilio Verify first
    try:
        result = twilio_client.verify.v2 \
            .services(TWILIO_VERIFY_SID) \
            .verification_checks \
            .create(to=phone, code=otp)

        if result.status == "approved":
            import sqlite3
            db   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "security.db")
            conn = sqlite3.connect(db)
            conn.execute("UPDATE users SET verified=1 WHERE phone=?", (phone,))
            conn.commit()
            conn.close()
            user = get_user(phone)
            print(f"[VERIFY] {phone} verified — role: {user['role']}")
            return jsonify({
                "status":  "verified",
                "message": "Phone verified successfully!",
                "role":    user["role"] if user else "user",
                "name":    user["name"] if user else "",
                "phone":   phone,
            }), 200
    except Exception as e:
        print(f"[VERIFY] Twilio error: {e}")

    # Fallback — check direct OTP
    if verify_user(phone, otp):
        user = get_user(phone)
        print(f"[VERIFY] {phone} verified via direct OTP")
        return jsonify({
            "status":  "verified",
            "message": "Phone verified!",
            "role":    user["role"] if user else "user",
            "name":    user["name"] if user else "",
            "phone":   phone,
        }), 200

    return jsonify({
        "status":  "failed",
        "message": "Wrong OTP. Please try again."
    }), 400

# ══════════════════════════════════════════════════════
#  VERIFIED USER ROUTES
# ══════════════════════════════════════════════════════

@app.route("/profile")
@require_verified
def profile():
    phone = get_phone_from_request()
    user  = get_user(phone)
    return jsonify({
        "id":            user["id"],
        "name":          user["name"],
        "phone":         user["phone"],
        "role":          user["role"],
        "registered_at": user["registered_at"],
    }), 200

@app.route("/intruders-json")
@require_verified
def intruders_json():
    return jsonify(get_all_intruders()), 200

# ── Alert from YOUR PC camera ──────────────────────────────────────────
@app.route("/alert", methods=["POST"])
def alert_trigger():
    data       = request.json or {}
    image_url  = data.get("image_url",  "")
    confidence = data.get("confidence", 0.0)
    label      = data.get("label",      "Unknown Person")
    ngrok      = data.get("ngrok_url",  NGROK_URL)

    save_intruder(image_url, confidence, label)

    live_url = f"{ngrok}/live"
    snap_url = f"{ngrok}/snapshot"

    phones = get_verified_phones()
    sent   = 0

    for phone in phones:
        # SMS
        try:
            twilio_client.messages.create(
                body=(
                    f"🚨 SECURITY ALERT!\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"Detected: {label}\n\n"
                    f"📹 Watch live:\n{live_url}\n\n"
                    f"📷 Snapshot:\n{snap_url}\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━"
                ),
                from_=TWILIO_NUMBER,
                to=phone
            )
            print(f"[ALERT] SMS sent to {phone}")
            sent += 1
        except Exception as e:
            print(f"[ALERT] SMS failed {phone}: {e}")

        # Call
        try:
            twilio_client.calls.create(
                to=phone,
                from_=TWILIO_NUMBER,
                twiml=(
                    f"<Response><Say voice='alice'>"
                    f"Security Alert! {label} detected. "
                    f"Check your SMS for the live video link."
                    f"</Say></Response>"
                )
            )
            print(f"[ALERT] Call made to {phone}")
        except Exception as e:
            print(f"[ALERT] Call failed {phone}: {e}")

    return jsonify({
        "status":         "alert sent",
        "users_notified": sent,
        "total_verified": len(phones)
    }), 200

# ══════════════════════════════════════════════════════
#  ADMIN ROUTES
# ══════════════════════════════════════════════════════

@app.route("/admin/users")
@require_admin
def admin_users():
    return jsonify(get_all_users()), 200

@app.route("/admin")
def admin_panel():
    phone = request.args.get("phone", "")
    if phone:
        phone = clean_phone(phone)
    else:
        phone = get_phone_from_request() or ""

    user = get_user(phone) if phone else None

    if not user or user["role"] != "admin":
        return render_template_string("""
<!DOCTYPE html><html>
<head><title>Access Denied</title>
<style>
  body{background:#0d0d0d;color:#fff;font-family:Arial;
       display:flex;align-items:center;justify-content:center;
       height:100vh;margin:0}
  .box{text-align:center;padding:40px;background:#1a1a1a;
       border-radius:16px;border:2px solid #cc0000}
  h2{color:#cc0000;margin-bottom:16px}
  p{color:#888;margin-top:8px;font-size:13px}
</style></head>
<body>
  <div class="box">
    <h2>🔒 Access Denied</h2>
    <p>Admin access only.</p>
    <p>Add ?phone=+91XXXXXXXXXX to URL</p>
  </div>
</body></html>
"""), 403

    users     = get_all_users()
    intruders = get_all_intruders()
    total     = len(users)
    verified  = sum(1 for u in users if u["verified"])

    rows = ""
    for u in users:
        v_badge = ("✅ Active" if u["verified"] else "❌ Pending")
        r_badge = ("👑 Admin"  if u["role"] == "admin" else "👤 User")
        rows += f"""
        <tr>
          <td>{u['id']}</td>
          <td>{u['name']}</td>
          <td>{u['phone']}</td>
          <td>{r_badge}</td>
          <td>{v_badge}</td>
          <td>{u['registered_at']}</td>
        </tr>"""

    if not rows:
        rows = "<tr><td colspan='6' style='text-align:center;color:#888;padding:30px'>No users yet</td></tr>"

    return render_template_string("""
<!DOCTYPE html><html>
<head>
  <title>Admin Panel</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#0d0d0d;color:#fff;font-family:Arial;padding:20px}
    h2{color:#cc0000;margin-bottom:20px}
    .top{display:flex;justify-content:space-between;
         align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:10px}
    .cards{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
    .card{background:#1a1a1a;border:1px solid #333;border-radius:12px;
          padding:16px 24px;min-width:120px;text-align:center;flex:1}
    .num{font-size:32px;font-weight:bold;color:#cc0000}
    .lbl{font-size:12px;color:#888;margin-top:4px}
    .btn{background:#333;color:#fff;border:none;padding:10px 18px;
         border-radius:8px;cursor:pointer;text-decoration:none;
         display:inline-block;font-size:14px}
    .btn-red{background:#cc0000}
    .buttons{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap}
    table{width:100%;border-collapse:collapse;font-size:13px}
    thead th{background:#cc0000;padding:12px 10px;text-align:left}
    tbody td{padding:12px 10px;border-bottom:1px solid #222}
    tbody tr:hover{background:#1a1a1a}
  </style>
</head>
<body>
  <div class="top">
    <h2>👑 Admin Panel — Security System</h2>
    <button class="btn" onclick="location.reload()">🔄 Refresh</button>
  </div>

  <div class="cards">
    <div class="card">
      <div class="num">""" + str(total) + """</div>
      <div class="lbl">Total Users</div>
    </div>
    <div class="card">
      <div class="num">""" + str(verified) + """</div>
      <div class="lbl">Verified</div>
    </div>
    <div class="card">
      <div class="num">""" + str(len(intruders)) + """</div>
      <div class="lbl">Detections</div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>ID</th><th>Name</th><th>Phone</th>
        <th>Role</th><th>Status</th><th>Registered</th>
      </tr>
    </thead>
    <tbody>""" + rows + """</tbody>
  </table>
</body></html>
""")

# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n[SERVER] Starting on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)