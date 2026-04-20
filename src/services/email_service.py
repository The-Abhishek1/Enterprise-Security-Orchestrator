"""
email_service.py — ESO direct email sender via Hostinger SMTP
Reads SMTP settings from pydantic Settings (which properly loads .env)
"""
import aiosmtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from src.utils.logging    import logger
from src.core.config      import get_settings


async def send_email(to: str, subject: str, html: str) -> bool:
    s = get_settings()
    if not s.smtp_password:
        logger.warning('[email] SMTP_PASSWORD not set — skipping email to %s', to)
        return False
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = f'XCloak <{s.smtp_user}>'
        msg['To']      = to
        msg.attach(MIMEText(html, 'html', 'utf-8'))

        await aiosmtplib.send(
            msg,
            hostname=s.smtp_host,
            port=s.smtp_port,
            username=s.smtp_user,
            password=s.smtp_password,
            use_tls=True,
        )
        logger.info('[email] ✓ sent "%s" to %s', subject, to)
        return True
    except Exception as e:
        logger.error('[email] ✗ failed "%s" to %s: %s', subject, to, e)
        return False


def _wrap(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title></head>
<body style="margin:0;padding:0;background:#0a0d14;font-family:'Courier New',monospace;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0d14;padding:32px 16px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0"
  style="background:#0f1219;border:1px solid rgba(255,255,255,0.08);border-radius:16px;overflow:hidden;max-width:560px;">
  <tr><td style="background:linear-gradient(135deg,#00ffaa10,#00aaff08);padding:24px 32px;border-bottom:1px solid rgba(255,255,255,0.06);">
    <table cellpadding="0" cellspacing="0" border="0">
      <tr>
        <td style="padding-right:12px;vertical-align:middle;">
          <!-- XCloak Shield Icon -->
          <img src="https://xcloak.tech/icon.png" alt="XCloak" width="40" height="40"
               style="display:block;border-radius:8px;"
               onerror="this.style.display='none'" />
        </td>
        <td style="vertical-align:middle;">
          <span style="font-size:22px;font-weight:900;color:#00ffaa;line-height:1;">X<span style="color:#e2e8f0;">cloak</span></span>
          <span style="display:block;font-size:10px;color:#475569;letter-spacing:3px;text-transform:uppercase;margin-top:2px;">Security Intelligence Platform</span>
        </td>
      </tr>
    </table>
  </td></tr>
  <tr><td style="padding:32px;">{body}</td></tr>
  <tr><td style="padding:20px 32px;border-top:1px solid rgba(255,255,255,0.06);background:rgba(0,0,0,0.2);">
    <p style="margin:0;font-size:10px;color:#334155;line-height:1.6;">
      You're receiving this because you have an account at
      <a href="https://xcloak.tech" style="color:#00ffaa;text-decoration:none;">xcloak.tech</a><br>
      Questions? Email <a href="mailto:admin@xcloak.tech" style="color:#00ffaa;text-decoration:none;">admin@xcloak.tech</a>
    </p>
  </td></tr>
</table></td></tr></table></body></html>"""


async def send_welcome(to: str, username: str):
    body = f"""
    <h1 style="margin:0 0 12px;font-size:20px;font-weight:900;color:#e2e8f0;">Welcome to XCloak 👋</h1>
    <p style="color:#94a3b8;font-size:14px;line-height:1.7;">
      Hey <strong style="color:#e2e8f0;">{username}</strong>, your account is ready.<br>
      AI-powered scanning, live CVEs, CTF challenges — all in one place.
    </p>
    <a href="https://xcloak.tech/scan/new"
       style="display:inline-block;margin-top:20px;padding:12px 28px;background:rgba(0,255,170,0.12);
              border:1px solid rgba(0,255,170,0.35);border-radius:10px;color:#00ffaa;
              font-size:13px;font-weight:700;text-decoration:none;">Start Scanning →</a>"""
    await send_email(to, 'Welcome to XCloak — Start Scanning', _wrap('Welcome', body))


async def send_password_reset(to: str, username: str, reset_url: str):
    body = f"""
    <h1 style="margin:0 0 12px;font-size:20px;font-weight:900;color:#e2e8f0;">Password Reset</h1>
    <p style="color:#94a3b8;font-size:14px;line-height:1.7;">
      Hey <strong style="color:#e2e8f0;">{username}</strong>,<br>
      Click below to reset your password. Link expires in <strong style="color:#ffd700;">30 minutes</strong>.
    </p>
    <a href="{reset_url}"
       style="display:inline-block;margin-top:20px;padding:12px 28px;background:rgba(255,58,92,0.12);
              border:1px solid rgba(255,58,92,0.35);border-radius:10px;color:#ff3a5c;
              font-size:13px;font-weight:700;text-decoration:none;">Reset Password →</a>
    <p style="margin-top:20px;font-size:11px;color:#475569;">
      Didn't request this? Ignore this email.
    </p>"""
    await send_email(to, 'XCloak — Reset your password', _wrap('Password Reset', body))


async def send_payment_confirmed(to: str, username: str, tier: str, amount_paise: int, payment_id: str):
    amount = amount_paise // 100
    body = f"""
    <h1 style="margin:0 0 12px;font-size:20px;font-weight:900;color:#e2e8f0;">Payment Confirmed 💳</h1>
    <p style="color:#94a3b8;font-size:14px;line-height:1.7;">
      Thanks <strong style="color:#e2e8f0;">{username}</strong>! Your
      <strong style="color:#00aaff;">{tier.upper()}</strong> plan is now active.
    </p>
    <div style="background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:16px;margin:16px 0;">
      <div style="display:flex;justify-content:space-between;padding:4px 0;font-size:12px;">
        <span style="color:#64748b;">Plan</span>
        <span style="color:#e2e8f0;font-weight:700;text-transform:capitalize;">{tier}</span>
      </div>
      <div style="display:flex;justify-content:space-between;padding:4px 0;font-size:14px;">
        <span style="color:#64748b;">Amount</span>
        <span style="color:#00ffaa;font-weight:900;">₹{amount:,}</span>
      </div>
      <div style="display:flex;justify-content:space-between;padding:4px 0;font-size:10px;">
        <span style="color:#64748b;">Payment ID</span>
        <span style="color:#475569;">{payment_id}</span>
      </div>
    </div>
    <a href="https://xcloak.tech/scan/new"
       style="display:inline-block;margin-top:8px;padding:12px 28px;background:rgba(0,170,255,0.12);
              border:1px solid rgba(0,170,255,0.35);border-radius:10px;color:#00aaff;
              font-size:13px;font-weight:700;text-decoration:none;">Start Scanning →</a>"""
    await send_email(to, f'XCloak — {tier.upper()} plan active · ₹{amount:,} received', _wrap('Payment', body))


async def send_scan_complete(to: str, username: str, target: str, scan_id: str,
                              risk_level: str, findings_count: int):
    color = {'critical': '#ff3a5c', 'high': '#ff8c42', 'medium': '#ffd700'}.get(risk_level, '#00ffaa')
    body = f"""
    <h1 style="margin:0 0 12px;font-size:20px;font-weight:900;color:#e2e8f0;">⚡ Scan Complete</h1>
    <p style="color:#94a3b8;font-size:14px;line-height:1.7;">
      Your scan of <strong style="color:#e2e8f0;">{target}</strong> finished, {username}.
    </p>
    <table style="width:100%;text-align:center;margin:16px 0;">
      <tr>
        <td style="padding:16px;">
          <div style="font-size:20px;font-weight:900;color:{color};">{risk_level.upper()}</div>
          <div style="font-size:9px;color:#475569;text-transform:uppercase;letter-spacing:2px;margin-top:4px;">Risk Level</div>
        </td>
        <td style="padding:16px;">
          <div style="font-size:20px;font-weight:900;color:#ff8c42;">{findings_count}</div>
          <div style="font-size:9px;color:#475569;text-transform:uppercase;letter-spacing:2px;margin-top:4px;">Findings</div>
        </td>
      </tr>
    </table>
    <a href="https://xcloak.tech/scan/{scan_id}"
       style="display:inline-block;margin-top:8px;padding:12px 28px;background:rgba(0,255,170,0.12);
              border:1px solid rgba(0,255,170,0.35);border-radius:10px;color:#00ffaa;
              font-size:13px;font-weight:700;text-decoration:none;">View Full Report →</a>"""
    await send_email(
        to,
        f'⚡ XCloak — {target} scan complete ({risk_level.upper()})',
        _wrap('Scan Complete', body)
    )
