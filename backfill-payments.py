#!/usr/bin/env python3
"""
backfill-payments.py — Sync Razorpay payment history into the ESO payments table.

Run from the ESO project directory:
    ./venv/bin/python3 backfill-payments.py

It fetches all captured payments from Razorpay and inserts any missing ones
into the local payments table, then upgrades user tiers accordingly.
"""
import asyncio, hashlib, os, sys
import asyncpg
import urllib.request, urllib.error, base64, json
from datetime import datetime

# ── Load .env manually (no python-dotenv needed) ─────────────────────────────
def load_env(path='.env'):
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"\''))
    except FileNotFoundError:
        pass

load_env('.env')
load_env('.env.local')

DSN         = os.environ.get('POSTGRES_DSN', 'postgresql://eso:eso_secret@localhost:5432/orchestrator')
RZP_KEY_ID  = os.environ.get('RAZORPAY_KEY_ID', '').strip('"\'  ')
RZP_SECRET  = os.environ.get('RAZORPAY_KEY_SECRET', '').strip('"\'  ')

if not RZP_KEY_ID or not RZP_SECRET:
    print("✗  RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET not set in .env")
    sys.exit(1)

# ── Razorpay HTTP helper (no aiohttp needed) ──────────────────────────────────
def rzp_get(path, params=None):
    url = f"https://api.razorpay.com/v1{path}"
    if params:
        url += '?' + '&'.join(f"{k}={v}" for k, v in params.items())
    creds = base64.b64encode(f"{RZP_KEY_ID}:{RZP_SECRET}".encode()).decode()
    req   = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"  Razorpay error {e.code}: {e.read().decode()[:200]}")
        return None

# ── Fetch all payments from Razorpay ─────────────────────────────────────────
def fetch_all_payments():
    payments = []
    skip = 0
    while True:
        data = rzp_get('/payments', {'count': 100, 'skip': skip})
        if not data or not data.get('items'):
            break
        items = data['items']
        payments.extend(items)
        print(f"  Fetched {len(payments)} payments so far...")
        if len(items) < 100:
            break
        skip += 100
    return payments

# ── Map Razorpay amount → tier ────────────────────────────────────────────────
def amount_to_tier(amount_paise):
    if amount_paise >= 499900:
        return 'enterprise'
    if amount_paise >= 99900:
        return 'pro'
    return 'free'

# ── Main backfill ─────────────────────────────────────────────────────────────
async def main():
    print(f"Connecting to DB: {DSN[:40]}...")
    conn = await asyncpg.connect(DSN)

    # Ensure payments table exists
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id         SERIAL PRIMARY KEY,
            payment_id TEXT UNIQUE NOT NULL,
            order_id   TEXT NOT NULL,
            user_id    TEXT NOT NULL,
            tier       TEXT NOT NULL,
            amount     INTEGER NOT NULL,
            status     TEXT NOT NULL DEFAULT 'captured',
            paid_at    TIMESTAMP DEFAULT NOW(),
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    print("✓  payments table ready")

    print(f"\nFetching payments from Razorpay ({RZP_KEY_ID[:15]}...)...")
    all_payments = fetch_all_payments()
    captured = [p for p in all_payments if p.get('status') == 'captured']
    print(f"  {len(all_payments)} total, {len(captured)} captured\n")

    inserted = 0
    upgraded = 0
    skipped  = 0

    for p in captured:
        payment_id = p['id']
        order_id   = p.get('order_id') or f"order_{payment_id}"
        amount     = p.get('amount', 0)
        tier       = amount_to_tier(amount)
        paid_at    = datetime.fromtimestamp(p['created_at']) if p.get('created_at') else None

        # Try to find the user by email from Razorpay payment details
        email = None
        if p.get('email'):
            email = p['email']
        elif p.get('contact'):
            pass  # email fetched via order notes below

        user_id = None
        if email:
            row = await conn.fetchrow(
                "SELECT user_id FROM users WHERE email=$1", email.lower()
            )
            if row:
                user_id = row['user_id']

        # Also check order notes for user_id by fetching the order
        if not user_id and p.get('order_id'):
            order_data = rzp_get(f"/orders/{p['order_id']}")
            if order_data:
                notes = order_data.get('notes') or {}
                uid   = notes.get('user_id')
                if uid:
                    row = await conn.fetchrow("SELECT user_id FROM users WHERE user_id=$1", uid)
                    if row:
                        user_id = row['user_id']
                # also try email from notes
                if not user_id and notes.get('email'):
                    row = await conn.fetchrow("SELECT user_id FROM users WHERE email=$1", notes['email'].lower())
                    if row:
                        user_id = row['user_id']

        if not user_id:
            print(f"  ✗  {payment_id[:24]} — no matching user (email: {email})")
            skipped += 1
            continue

        # Insert payment record
        try:
            await conn.execute(
                """INSERT INTO payments (payment_id, order_id, user_id, tier, amount, status, paid_at)
                   VALUES ($1, $2, $3, $4, $5, 'captured', $6)
                   ON CONFLICT (payment_id) DO NOTHING""",
                payment_id, order_id, user_id, tier, amount, paid_at
            )
            inserted += 1
        except Exception as e:
            print(f"  ✗  Insert failed for {payment_id}: {e}")
            skipped += 1
            continue

        # Upgrade user tier if needed
        user_row = await conn.fetchrow("SELECT tier FROM users WHERE user_id=$1", user_id)
        tier_rank = {'free': 0, 'pro': 1, 'enterprise': 2, 'admin': 3}
        current_rank = tier_rank.get(user_row['tier'] if user_row else 'free', 0)
        new_rank     = tier_rank.get(tier, 0)

        if new_rank > current_rank:
            await conn.execute(
                "UPDATE users SET tier=$1, updated_at=NOW() WHERE user_id=$2",
                tier, user_id
            )
            upgraded += 1
            print(f"  ✓  {payment_id[:24]} — ₹{amount//100} — {email} → upgraded to {tier}")
        else:
            print(f"  ✓  {payment_id[:24]} — ₹{amount//100} — {email} ({user_row['tier'] if user_row else '?'} already)")

    await conn.close()

    print(f"\n✅  Done!")
    print(f"   Inserted: {inserted} payment records")
    print(f"   Upgraded: {upgraded} user tiers")
    print(f"   Skipped:  {skipped} (no matching user)")
    print(f"\n   Refresh the admin panel Payments tab to see results.")

asyncio.run(main())
