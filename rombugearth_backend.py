"""
ROMbug Earth licensing backend
a ROMbug enterprise

A small Flask service that sits between Stripe, VPNresellers, and the ROMbug Earth
desktop app. It has no web pages — it exists only because two secrets (the
Stripe key and the VPNresellers reseller token) must never ship inside the
downloadable .exe.

Flow
----
1.  App calls  POST /checkout      -> returns a Stripe Checkout URL
2.  User pays in their browser
3.  Stripe calls POST /stripe/webhook (server-to-server)
        - on checkout.session.completed:
            * provision a VPNresellers account
            * mint a licence key
            * email it to the customer
        - on customer.subscription.deleted / unpaid:
            * disable the VPN account
4.  App calls  POST /license/validate  with the key
        -> returns the WireGuard config + server list, or an error

Environment variables (set these in Render)
-------------------------------------------
STRIPE_SECRET_KEY          sk_live_... (reuse from Floor113 or a new account)
STRIPE_WEBHOOK_SECRET      whsec_...   (from the webhook you register)
STRIPE_PRICE_ID            price_...   (a $7.99/month recurring Price)
VPNR_TOKEN                 VPNresellers reseller API bearer token
VPNR_PROJECT_ID            a project id created once in your VPNresellers panel
RESEND_API_KEY             (optional) to email licence keys; reuse Floor113's
MAIL_FROM                  e.g. "ROMbug Earth <noreply@rombug.com>"
PUBLIC_URL                 this service's own URL, e.g. https://atlasvpn-api.onrender.com
DATABASE_PATH              (optional) sqlite path, defaults to ./atlas.db

Deploy on Render exactly like your other backends:
    Build:  pip install -r requirements.txt
    Start:  gunicorn rombugearth_backend:app
    Add a persistent disk mounted at /data and set DATABASE_PATH=/data/atlas.db
"""

import os
import json
import secrets
import sqlite3
import time
import ipaddress
import datetime as dt

import stripe
import requests
from flask import Flask, request, jsonify

# ── config ──────────────────────────────────────────────────────────────
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
PRICE_ID = os.getenv("STRIPE_PRICE_ID", "")

VPNR_BASE = "https://api.vpnresellers.com/v4_1"
VPNR_TOKEN = os.getenv("VPNR_TOKEN", "")
VPNR_PROJECT_ID = os.getenv("VPNR_PROJECT_ID", "")

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
MAIL_FROM = os.getenv("MAIL_FROM", "ROMbug Earth <noreply@rombug.com>")
PUBLIC_URL = os.getenv("PUBLIC_URL", "").rstrip("/")
DB_PATH = os.getenv("DATABASE_PATH", "atlas.db")

app = Flask(__name__)


# ── storage ─────────────────────────────────────────────────────────────
def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = db()
    c.execute("""CREATE TABLE IF NOT EXISTS licenses(
        license_key   TEXT PRIMARY KEY,
        email         TEXT,
        vpnr_account_id   INTEGER,
        vpnr_username     TEXT,
        vpnr_password     TEXT,
        stripe_customer   TEXT,
        stripe_subscription TEXT,
        status        TEXT DEFAULT 'active',   -- active | cancelled
        created_at    TEXT,
        updated_at    TEXT)""")
    # map a checkout session back to the customer email before payment lands
    c.execute("""CREATE TABLE IF NOT EXISTS pending(
        session_id TEXT PRIMARY KEY,
        email      TEXT,
        created_at TEXT)""")
    c.commit()
    c.close()


init_db()


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


# ── VPNresellers helpers ────────────────────────────────────────────────
def vpnr(method, path, **kw):
    """Call the reseller API. The token never leaves this server."""
    headers = {
        "Authorization": f"Bearer {VPNR_TOKEN}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    r = requests.request(method, f"{VPNR_BASE}{path}",
                         headers=headers, timeout=20, **kw)
    return r


def provision_account(email):
    """Create a fresh VPN account. Returns (account_id, username, password)."""
    username = "atlas_" + secrets.token_hex(8)          # opaque, unique
    password = secrets.token_urlsafe(18)
    body = {
        "username": username,
        "password": password,
        "customer": {
            "first_name": "ROMbugEarth",
            "last_name": "Subscriber",
            "email": email,
            "project_id": int(VPNR_PROJECT_ID) if VPNR_PROJECT_ID else None,
        },
    }
    r = vpnr("POST", "/accounts", data=json.dumps(body))

    # documented failure modes, surfaced clearly
    if r.status_code == 402:
        raise RuntimeError("VPNresellers balance is empty — top up credit.")
    if r.status_code == 422:
        # usually a duplicate customer email; retry without the customer block
        r = vpnr("POST", "/accounts",
                 data=json.dumps({"username": username, "password": password}))
    r.raise_for_status()
    acc = r.json()["data"]
    return acc["id"], username, password


def set_account_enabled(account_id, enabled):
    verb = "enable" if enabled else "disable"
    vpnr("PUT", f"/accounts/{account_id}/{verb}")


def list_servers():
    r = vpnr("GET", "/servers")
    r.raise_for_status()
    data = r.json().get("data", [])
    # lower capacity value = less loaded; surface those first
    return sorted(data, key=lambda s: s.get("capacity", 0))


def wireguard_config(server_id, account_id):
    r = vpnr("GET", "/configuration/wireguard",
             params={"server_id": server_id, "account_id": account_id})
    r.raise_for_status()
    return r.json()["data"]["content"]


# ── email ───────────────────────────────────────────────────────────────
def email_license(to_addr, key):
    """
    Send the licence key. Returns (ok, detail) so callers/diagnostics can see
    what happened \u2014 a silent failure here is why a customer would pay and
    never receive their key.
    """
    if not RESEND_API_KEY:
        app.logger.warning("RESEND_API_KEY not set \u2014 licence email skipped")
        return False, "RESEND_API_KEY not set"
    html = f"""
    <div style="font-family:Segoe UI,sans-serif;color:#16233a">
      <h2 style="color:#1a44b8">Your ROMbug Earth licence key</h2>
      <p>Thank you for activating the VPN in ROMbug Earth.</p>
      <p style="font-size:18px"><b style="letter-spacing:2px">{key}</b></p>
      <p>Open ROMbug Earth, go to the <b>VPN</b> tab, choose
      <b>I already have a licence key</b>, and paste it in. Your VPN unlocks
      immediately.</p>
      <p style="font-size:13px;color:#5a6880">You can cancel or change your
      payment details at any time here:<br>
      <a href="{PUBLIC_URL}/manage">{PUBLIC_URL}/manage</a><br>
      Keep this email \u2014 you will need the key above to manage your
      subscription.</p>
      <p style="color:#6b7a91;font-size:12px">a ROMbug enterprise \u2014
      rombug.com</p>
    </div>"""
    try:
        r = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={"from": MAIL_FROM, "to": [to_addr],
                  "subject": "Your ROMbug Earth licence key", "html": html},
            timeout=15)
    except Exception as e:
        app.logger.error("Resend request failed: %s", e)
        return False, f"request failed: {e}"

    if r.status_code >= 300:
        # Most common causes: unverified sender domain, or a free-tier account
        # that may only deliver to the address the Resend account was made with.
        app.logger.error("Resend rejected the email (%s): %s",
                         r.status_code, r.text[:400])
        return False, f"HTTP {r.status_code}: {r.text[:300]}"

    app.logger.info("Licence email sent to %s", to_addr)
    return True, "sent"


# ── routes ──────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return jsonify(ok=True, service="rombugearth-license", ts=now())


@app.get("/vpnr-check")
def vpnr_check():
    """
    Diagnostic: confirms the VPNresellers token works and shows your balance.
    Hit this once after adding VPNR_TOKEN to Render. Does NOT expose the token.
    """
    try:
        r = vpnr("GET", "/profile")
        if r.status_code == 200:
            bal = r.json().get("data", {}).get("balance", "?")
            srv = vpnr("GET", "/servers")
            n = len(srv.json().get("data", [])) if srv.status_code == 200 else 0
            return jsonify(ok=True, balance=bal, servers=n,
                           project_id=VPNR_PROJECT_ID or "(not set)")
        return jsonify(ok=False, status=r.status_code,
                       hint="Token rejected — check VPNR_TOKEN."), 502
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 502


@app.post("/checkout")
def checkout():
    """App asks for a Stripe Checkout URL. Body: {"email": "..."}"""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email or "@" not in email:
        return jsonify(error="A valid email is required."), 400

    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            payment_method_types=["card"],
            line_items=[{"price": PRICE_ID, "quantity": 1}],
            customer_email=email,
            # Shows the "Add promotion code" box on Stripe's hosted page, so a
            # 100%-off coupon can be redeemed. Platform-agnostic: the Windows
            # and Linux apps both just open the URL this endpoint returns.
            allow_promotion_codes=True,
            metadata={"product": "rombugearth_vpn", "email": email},
            success_url=f"{PUBLIC_URL}/paid?ok=1",
            cancel_url=f"{PUBLIC_URL}/paid?ok=0",
        )
    except stripe.StripeError as e:
        return jsonify(error=str(e)), 502

    c = db()
    c.execute("INSERT OR REPLACE INTO pending(session_id,email,created_at) "
              "VALUES(?,?,?)", (session.id, email, now()))
    c.commit()
    c.close()
    return jsonify(checkout_url=session.url)


@app.get("/paid")
def paid():
    """Tiny confirmation page the browser lands on after Stripe."""
    ok = request.args.get("ok") == "1"
    msg = ("Payment received. Your licence key is on its way by email — "
           "paste it into ROMbug Earth to unlock your VPN."
           if ok else "Checkout cancelled. You can try again from ROMbug Earth.")
    return f"""<!doctype html><meta charset=utf-8>
    <meta name=viewport content="width=device-width,initial-scale=1">
    <title>ROMbug Earth</title>
    <body style="font-family:'Segoe UI',system-ui,sans-serif;
    background:#0f2f8f;color:#fff;text-align:center;padding:80px 20px">
    <h1 style="letter-spacing:2px;font-size:26px">ROMbug Earth</h1>
    <p style="font-size:16px;max-width:460px;margin:20px auto;
    line-height:1.6">{msg}</p>
    <p style="opacity:.75;font-size:14px;max-width:460px;margin:0 auto">
    The email can take a few minutes to arrive \u2014 check your spam folder
    if you do not see it.</p>
    <p style="margin-top:34px">
      <a href="{PUBLIC_URL}/manage" style="color:#ffd400;font-size:14px">
      Manage or cancel your subscription</a></p>
    <p style="opacity:.6;margin-top:26px">You can close this tab.</p>
    </body>"""


@app.get("/manage")
def manage_page():
    """
    Self-service page: a customer pastes their licence key and is taken to
    Stripe's Customer Portal, where they can cancel, change card, or download
    invoices. Being able to cancel easily is both a legal expectation and the
    cheapest way to avoid chargebacks \u2014 a customer who cannot find the
    cancel button disputes the charge instead.
    """
    return """<!doctype html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Manage your ROMbug Earth subscription</title>
<style>
 body{font-family:'Segoe UI',system-ui,sans-serif;background:#f2f5fa;
   color:#16233a;margin:0;padding:40px 20px;display:flex;
   justify-content:center}
 .card{background:#fff;border:1px solid #e2e7f0;border-radius:16px;
   padding:38px;max-width:460px;width:100%;
   box-shadow:0 18px 40px -24px rgba(22,35,58,.35)}
 h1{margin:0 0 6px;font-size:22px;letter-spacing:-.3px}
 p{color:#5a6880;font-size:14.5px;line-height:1.55}
 input{width:100%;box-sizing:border-box;padding:13px 15px;font-size:15px;
   border:1px solid #d4dae6;border-radius:10px;margin:14px 0 8px;
   font-family:Consolas,monospace;letter-spacing:1px}
 input:focus{outline:none;border-color:#1a44b8}
 button{width:100%;padding:14px;font-size:15px;font-weight:700;color:#fff;
   background:#1a44b8;border:none;border-radius:10px;cursor:pointer}
 button:hover{background:#0f2f8f}
 .err{color:#c9302c;font-size:14px;min-height:20px;margin-top:10px}
 .foot{margin-top:22px;font-size:12.5px;color:#7d8ba1}
</style>
<div class=card>
  <h1>Manage your subscription</h1>
  <p>Enter the licence key from your confirmation email. You can cancel,
     update your card, or view invoices.</p>
  <input id=k placeholder="ROMBUG-XXXX-XXXX-XXXX-XXXX" autocomplete=off>
  <button onclick=go()>Continue</button>
  <div class=err id=e></div>
  <div class=foot>Lost your key? Email support and we will look it up.</div>
</div>
<script>
async function go(){
  var k=document.getElementById('k').value.trim();
  var e=document.getElementById('e');
  e.textContent='';
  if(!k){ e.textContent='Please enter your licence key.'; return; }
  try{
    var r=await fetch('/portal',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({license_key:k})});
    var d=await r.json();
    if(r.ok && d.url){ window.location = d.url; }
    else { e.textContent = d.error || 'That key was not recognised.'; }
  }catch(err){ e.textContent='Something went wrong. Please try again.'; }
}
document.getElementById('k').addEventListener('keydown',function(ev){
  if(ev.key==='Enter') go();
});
</script>"""


@app.post("/portal")
def portal():
    """
    Swap a licence key for a Stripe Customer Portal session. The portal is
    hosted by Stripe, so cancellation, card updates and invoices all work
    without us building or securing any of that ourselves.
    """
    data = request.get_json(silent=True) or {}
    key = (data.get("license_key") or "").strip().upper()
    if not key:
        return jsonify(error="A licence key is required."), 400

    c = db()
    row = c.execute("SELECT stripe_customer FROM licenses WHERE license_key=?",
                    (key,)).fetchone()
    c.close()
    if not row or not row["stripe_customer"]:
        return jsonify(error="That licence key was not recognised."), 404
    if str(row["stripe_customer"]).startswith("TEST"):
        return jsonify(error="Test licences have no billing to manage."), 400

    try:
        sess = stripe.billing_portal.Session.create(
            customer=row["stripe_customer"],
            return_url=f"{PUBLIC_URL}/manage")
    except Exception as e:
        app.logger.error("portal session failed: %s", e)
        return jsonify(error="Could not open the billing portal."), 502
    return jsonify(url=sess.url)


@app.post("/stripe/webhook")
def webhook():
    payload = request.get_data()
    sig = request.headers.get("Stripe-Signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, WEBHOOK_SECRET)
    except (ValueError, stripe.SignatureVerificationError):
        return "bad signature", 400

    kind = event["type"]
    obj = event["data"]["object"]

    if kind == "checkout.session.completed":
        _fulfil(obj)
    elif kind in ("customer.subscription.deleted",
                  "customer.subscription.paused"):
        _revoke(sfield(obj, "id"))
    # invoice.payment_failed could also revoke after a grace period; left
    # simple here.

    return jsonify(received=True)


def sfield(obj, key, default=None):
    """
    Read a field from a Stripe payload safely.

    Stripe's library hands back StripeObject, which overrides attribute access
    so a plain .get() raises AttributeError. Dicts and StripeObjects both
    support subscript access, so use that and fall back to the default.
    """
    if obj is None:
        return default
    try:
        val = obj[key]
    except (KeyError, TypeError, AttributeError):
        return default
    return default if val is None else val


def _fulfil(session):
    """A subscription was paid. Provision the VPN and mint a licence key."""
    email = (sfield(session, "customer_email")
             or sfield(sfield(session, "metadata"), "email")
             or "")
    email = str(email).strip().lower()
    sub = sfield(session, "subscription")
    cust = sfield(session, "customer")

    # customer_details.email is where Checkout puts the address the buyer typed
    if not email:
        email = str(sfield(sfield(session, "customer_details"), "email")
                    or "").strip().lower()
    if not email:
        return

    # idempotency: if this subscription already has a licence, stop.
    c = db()
    row = c.execute("SELECT license_key FROM licenses WHERE "
                    "stripe_subscription=?", (sub,)).fetchone()
    if row:
        c.close()
        return

    account_id, username, password = provision_account(email)
    key = "ROMBUG-" + "-".join(
        secrets.token_hex(2).upper() for _ in range(4))   # ROMBUG-1A2B-...

    c.execute("""INSERT INTO licenses(license_key,email,vpnr_account_id,
        vpnr_username,vpnr_password,stripe_customer,stripe_subscription,
        status,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,'active',?,?)""",
              (key, email, account_id, username, password, cust, sub,
               now(), now()))
    c.commit()
    c.close()
    email_license(email, key)


def _revoke(subscription_id):
    if not subscription_id:
        return
    c = db()
    row = c.execute("SELECT vpnr_account_id FROM licenses WHERE "
                    "stripe_subscription=?", (subscription_id,)).fetchone()
    if row:
        try:
            set_account_enabled(row["vpnr_account_id"], False)
        except Exception:
            pass
        c.execute("UPDATE licenses SET status='cancelled',updated_at=? "
                  "WHERE stripe_subscription=?", (now(), subscription_id))
        c.commit()
    c.close()


@app.post("/test/provision")
def test_provision():
    """
    TEST ONLY. Provisions a real VPN account and mints a licence key WITHOUT
    any Stripe payment, so the VPN tunnel path can be tested end to end.

    Gated by TEST_SECRET (an env var). If TEST_SECRET is unset, this endpoint
    is disabled entirely \u2014 so it is safe to leave in production as long
    as you never set TEST_SECRET there (or set it, test, then remove it).

    Body: {"secret": "...", "email": "you@example.com"}
    Returns: {"license_key": "ROMBUG-...."}
    """
    want = os.getenv("TEST_SECRET", "")
    if not want:
        return jsonify(error="Test provisioning is disabled."), 404
    data = request.get_json(silent=True) or {}
    if data.get("secret") != want:
        return jsonify(error="Bad test secret."), 403

    email = (data.get("email") or "test@rombug.com").lower()
    # reuse the exact same provisioning path a real payment would trigger
    c = db()
    row = c.execute("SELECT license_key FROM licenses WHERE email=? AND "
                    "stripe_subscription LIKE 'TEST-%'", (email,)).fetchone()
    if row:
        c.close()
        return jsonify(license_key=row["license_key"], reused=True)

    try:
        account_id, username, password = provision_account(email)
    except Exception as e:
        c.close()
        return jsonify(error=f"Provision failed: {e}"), 502

    key = "ROMBUG-" + "-".join(
        secrets.token_hex(2).upper() for _ in range(4))
    c.execute("""INSERT INTO licenses(license_key,email,vpnr_account_id,
        vpnr_username,vpnr_password,stripe_customer,stripe_subscription,
        status,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,'active',?,?)""",
              (key, email, account_id, username, password, "TEST",
               "TEST-" + secrets.token_hex(4), now(), now()))
    c.commit()
    c.close()
    return jsonify(license_key=key, account_id=account_id, test=True)


@app.post("/admin/lookup")
def admin_lookup():
    """
    Find a customer's licence key by email. For support ("I lost my key") and
    for recovering a key when the notification email failed to send.

    Gated by ADMIN_SECRET \u2014 if that env var is unset the endpoint is
    disabled entirely, so it is safe to leave deployed.

    Body: {"secret": "...", "email": "buyer@example.com", "resend": true}
    """
    want = os.getenv("ADMIN_SECRET", "")
    if not want:
        return jsonify(error="Admin lookup is disabled."), 404
    data = request.get_json(silent=True) or {}
    if data.get("secret") != want:
        return jsonify(error="Bad admin secret."), 403

    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify(error="An email is required."), 400

    c = db()
    rows = c.execute(
        "SELECT license_key,email,status,created_at FROM licenses "
        "WHERE email=? ORDER BY created_at DESC", (email,)).fetchall()
    c.close()
    if not rows:
        return jsonify(found=False,
                       error="No licence found for that email."), 404

    out = [{"license_key": r["license_key"], "status": r["status"],
            "created_at": r["created_at"]} for r in rows]

    # optionally re-send the key by email (no-op if Resend isn't configured)
    if data.get("resend") and RESEND_API_KEY:
        try:
            email_license(email, out[0]["license_key"])
        except Exception:
            pass

    return jsonify(found=True, email=email, licenses=out,
                   emailed=bool(data.get("resend") and RESEND_API_KEY))


@app.post("/admin/test-email")
def admin_test_email():
    """
    Send a test email and report exactly what Resend said. Use this when a
    customer says the key never arrived. Gated by ADMIN_SECRET.

    Body: {"secret": "...", "email": "you@example.com"}
    """
    want = os.getenv("ADMIN_SECRET", "")
    if not want:
        return jsonify(error="Admin endpoints are disabled."), 404
    data = request.get_json(silent=True) or {}
    if data.get("secret") != want:
        return jsonify(error="Bad admin secret."), 403
    to = (data.get("email") or "").strip()
    if not to:
        return jsonify(error="An email is required."), 400

    ok, detail = email_license(to, "ROMBUG-TEST-TEST-TEST-TEST")
    return jsonify(ok=ok, detail=detail, mail_from=MAIL_FROM,
                   resend_key_set=bool(RESEND_API_KEY)), (200 if ok else 502)


@app.post("/license/validate")
def validate():
    """
    ROMbug Earth calls this on launch and when connecting.
    Body: {"license_key": "ROMBUG-...."}
    Returns the server list and account id so the app can then request a
    per-server WireGuard config. The reseller token is never exposed.
    """
    data = request.get_json(silent=True) or {}
    key = (data.get("license_key") or "").strip().upper()
    c = db()
    row = c.execute("SELECT * FROM licenses WHERE license_key=?",
                    (key,)).fetchone()
    c.close()
    if not row:
        return jsonify(valid=False, error="Unknown licence key."), 404
    if row["status"] != "active":
        return jsonify(valid=False,
                       error="This licence has been cancelled."), 403

    try:
        servers = [
            {"id": s["id"], "name": s["name"], "country": s["country_code"],
             "city": s.get("city", "")}
            for s in list_servers()
        ]
    except Exception:
        servers = []

    return jsonify(valid=True, account_id=row["vpnr_account_id"],
                   servers=servers)


@app.post("/license/config")
def config():
    """
    ROMbug Earth asks for a WireGuard config for one server.
    Body: {"license_key": "...", "server_id": 3}
    Returns the .conf text. This is the only place the tunnel secret is
    handed to the client, and only after the licence is checked.
    """
    data = request.get_json(silent=True) or {}
    key = (data.get("license_key") or "").strip().upper()
    server_id = data.get("server_id")

    c = db()
    row = c.execute("SELECT * FROM licenses WHERE license_key=?",
                    (key,)).fetchone()
    c.close()
    if not row or row["status"] != "active":
        return jsonify(error="Invalid or cancelled licence."), 403
    if not server_id:
        return jsonify(error="server_id is required."), 400

    try:
        conf = wireguard_config(server_id, row["vpnr_account_id"])
    except Exception as e:
        return jsonify(error=f"Could not fetch config: {e}"), 502
    return jsonify(config=conf)


# ── free privacy test ───────────────────────────────────────────────────
#
# Backs the public page at rombugearth.com/privacy-check. That page reads
# almost everything from the browser itself, but a browser cannot see its
# own public address, so this route reports the address the request arrived
# from plus a geo/ASN lookup.
#
# Deliberately: nothing is written to the database, nothing is logged, and
# the only retention is a ten-minute in-memory cache to keep the ipinfo
# quota down. Gunicorn writes no access log unless you pass
# --access-logfile, so leave that flag off and the page's "we don't save
# your results" line stays true.
#
# Environment variables
#   IPINFO_TOKEN       required. Free Lite token: ipinfo.io/dashboard/lite
#   IPINFO_PLAN        "lite" (default) or "core" if you upgrade to a paid plan
#   PRIVACY_ORIGINS    comma-separated origins allowed to call this route
#   CLIENT_IP_HEADER   set to e.g. CF-Connecting-IP if a CDN fronts Render
#
# Lite is free with unlimited requests but returns country and ASN only —
# no city, region or time zone — and IPinfo require visible attribution
# when the data is shown publicly. The page carries that credit in its
# footer; don't remove it. Set IPINFO_PLAN=core on a paid token and the
# city and time-zone rows light up on their own.

PRIVACY_ORIGINS = {
    o.strip().rstrip("/")
    for o in os.getenv(
        "PRIVACY_ORIGINS",
        "https://www.rombugearth.com,https://rombugearth.com,"
        "http://localhost:8888,http://127.0.0.1:8888",
    ).split(",")
    if o.strip()
}
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")
IPINFO_PLAN = os.getenv("IPINFO_PLAN", "lite").strip().lower()
CLIENT_IP_HEADER = os.getenv("CLIENT_IP_HEADER", "").strip()

GEO_TTL = 600          # seconds to keep a lookup in memory
RATE_MAX = 20          # requests per address per window
RATE_WINDOW = 60

_geo_cache = {}        # ip -> (expires_at, payload)
_rate = {}             # ip -> [timestamps]

# Substrings that mean "datacentre, hosting or VPN" rather than "a house".
_HOSTING_WORDS = (
    "hosting", "host", "datacenter", "datacentre", "data center", "cloud",
    "server", "colo", "vpn", "proxy", "digitalocean", "linode", "vultr",
    "ovh", "hetzner", "amazon", "aws", "google llc", "google cloud",
    "microsoft", "azure", "oracle", "cloudflare", "leaseweb", "choopa",
    "contabo", "scaleway", "m247", "datacamp", "packethub", "nforce",
    "quadranet", "psychz", "zenlayer", "hostwinds", "ipxo", "clouvider",
)


def _privacy_cors(resp):
    """Allow only our own front end to read this route."""
    origin = (request.headers.get("Origin") or "").rstrip("/")
    if origin in PRIVACY_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        resp.headers["Access-Control-Max-Age"] = "600"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _client_ip():
    """
    The address this request actually came from.

    Render appends the real client to whatever X-Forwarded-For the caller
    sent, so the LAST hop is the trustworthy one. If you put a CDN in front
    of Render, set CLIENT_IP_HEADER to the header it provides instead —
    don't trust those headers by default, since a visitor can forge them.
    """
    if CLIENT_IP_HEADER:
        v = (request.headers.get(CLIENT_IP_HEADER) or "").strip()
        if v:
            return v.split(",")[0].strip()
    xff = request.headers.get("X-Forwarded-For", "")
    hops = [p.strip() for p in xff.split(",") if p.strip()]
    if hops:
        return hops[-1]
    return request.remote_addr or ""


def _rate_ok(ip):
    now_ts = time.time()
    hits = [t for t in _rate.get(ip, []) if now_ts - t < RATE_WINDOW]
    hits.append(now_ts)
    _rate[ip] = hits
    if len(_rate) > 5000:          # crude cap so this can't grow unbounded
        _rate.clear()
    return len(hits) <= RATE_MAX


def _looks_like_hosting(*names):
    low = " ".join(n or "" for n in names).lower()
    return any(w in low for w in _HOSTING_WORDS)


def _lite(ip):
    """
    IPinfo Lite: free, unlimited, token required.
    Returns country + continent + ASN only — no city, region or time zone.
    https://api.ipinfo.io/lite/<ip>?token=...
    """
    r = requests.get(f"https://api.ipinfo.io/lite/{ip}",
                     params={"token": IPINFO_TOKEN}, timeout=6,
                     headers={"Accept": "application/json"})
    if r.status_code != 200:
        return {}
    d = r.json()
    return {
        "city": "",
        "region": "",
        "country": d.get("country") or "",
        "country_code": d.get("country_code") or "",
        "continent": d.get("continent") or "",
        "org": d.get("as_name") or "",
        "asn": d.get("asn") or "",
        "as_domain": d.get("as_domain") or "",
        "timezone": "",
        "hosting": _looks_like_hosting(d.get("as_name"), d.get("as_domain")),
        "precision": "country",
        "attribution": "IPinfo Lite",
    }


def _core(ip):
    """
    IPinfo Core (paid): adds city, region, time zone and authoritative
    hosting/anonymous flags. Only used when IPINFO_PLAN=core.
    """
    r = requests.get(f"https://ipinfo.io/{ip}/json",
                     params={"token": IPINFO_TOKEN}, timeout=6,
                     headers={"Accept": "application/json"})
    if r.status_code != 200:
        return {}
    d = r.json()

    # Core nests ASN data; the older flat shape puts it in org as "AS123 Name".
    asn_obj = d.get("asn")
    if isinstance(asn_obj, dict):
        asn = asn_obj.get("asn") or ""
        org = asn_obj.get("name") or ""
        as_domain = asn_obj.get("domain") or ""
        as_type = (asn_obj.get("type") or "").lower()
    else:
        asn, as_domain, as_type = "", "", ""
        org = (d.get("org") or "").strip()
        if org.startswith("AS"):
            bits = org.split(" ", 1)
            asn = bits[0]
            org = bits[1] if len(bits) > 1 else ""

    # Prefer IPinfo's own flags where the plan supplies them.
    hosting = bool(d.get("hosting")) or as_type == "hosting"
    if not hosting and not d.get("hosting"):
        hosting = _looks_like_hosting(org, as_domain)

    return {
        "city": d.get("city") or "",
        "region": d.get("region") or "",
        "country": d.get("country") or "",
        "country_code": d.get("country") or "",
        "continent": "",
        "org": org,
        "asn": asn,
        "as_domain": as_domain,
        "timezone": d.get("timezone") or "",
        "hosting": hosting,
        "anonymous": bool(d.get("anonymous") or d.get("vpn") or d.get("proxy")),
        "precision": "city",
        "attribution": "IPinfo",
    }


def _geo(ip):
    """Look the address up, with a short in-memory cache. {} on any failure."""
    now_ts = time.time()
    hit = _geo_cache.get(ip)
    if hit and hit[0] > now_ts:
        return hit[1]

    out = {}
    if IPINFO_TOKEN:
        try:
            out = _core(ip) if IPINFO_PLAN == "core" else _lite(ip)
        except Exception:
            out = {}

    if len(_geo_cache) > 2000:
        _geo_cache.clear()
    _geo_cache[ip] = (now_ts + GEO_TTL, out)
    return out


@app.route("/privacy/check", methods=["GET", "OPTIONS"])
def privacy_check():
    if request.method == "OPTIONS":
        return _privacy_cors(app.make_default_options_response())

    ip = _client_ip()
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return _privacy_cors(jsonify(ok=False,
                                     error="Couldn't read your address.")), 400

    if not _rate_ok(ip):
        return _privacy_cors(jsonify(ok=False,
                                     error="Too many tests. Try again in a minute.")), 429

    body = {"ok": True, "ip": ip, "version": parsed.version,
            "precision": "none", "plan": IPINFO_PLAN}
    if parsed.is_private or parsed.is_loopback:
        body.update(city="", region="", country="", org="Private network",
                    asn="", timezone="", hosting=False, local=True)
    elif not IPINFO_TOKEN:
        # No token configured: still report the address, say why the rest is blank.
        body.update(city="", region="", country="", org="", asn="",
                    timezone="", hosting=False,
                    note="Address lookup isn't configured on this server.")
    else:
        body.update(_geo(ip))
    return _privacy_cors(jsonify(**body))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
