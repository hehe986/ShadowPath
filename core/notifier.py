"""
core/notifier.py - Notification Engine
=======================================
Kirim ringkasan hasil scan ke Discord atau Telegram via webhook/bot API.
Murni pakai requests, tanpa dependency tambahan.

Konfigurasi via config.py atau environment variable:
  DISCORD_WEBHOOK_URL
  TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID
"""

import json
import requests

from utils.logger import Logger


class Notifier:
    """Kirim notifikasi hasil scan ke Discord/Telegram."""

    def __init__(self,
                 discord_webhook: str = "",
                 telegram_token: str = "",
                 telegram_chat_id: str = ""):
        self.discord_webhook  = discord_webhook
        self.telegram_token   = telegram_token
        self.telegram_chat_id = telegram_chat_id

    @property
    def enabled(self) -> bool:
        return bool(self.discord_webhook or
                    (self.telegram_token and self.telegram_chat_id))

    # =============================================================
    # PUBLIC API
    # =============================================================
    def notify_scan_complete(self, summary: dict):
        """
        Kirim ringkasan hasil scan.

        Args:
            summary: dict berisi ringkasan scan (target, mode, counts, dll)
        """
        if not self.enabled:
            return

        text = self._format_summary(summary)

        if self.discord_webhook:
            self._send_discord(text, summary)
        if self.telegram_token and self.telegram_chat_id:
            self._send_telegram(text)

    # =============================================================
    # FORMATTING
    # =============================================================
    def _format_summary(self, s: dict) -> str:
        """Format ringkasan jadi text (plain, dipakai Telegram)."""
        lines = [
            f"🎯 ShadowPath Scan Complete",
            f"",
            f"Target : {s.get('target', '?')}",
            f"Mode   : {s.get('mode', '?').upper()}",
            f"Time   : {s.get('elapsed', '?')}",
            f"",
        ]

        # Subdomain stats (recon mode)
        if "subdomains" in s:
            sub = s["subdomains"]
            lines += [
                f"📡 Subdomains",
                f"  Total : {sub.get('total', 0)}",
                f"  Live  : {sub.get('live', 0)}",
                f"",
            ]

        # Endpoint stats
        if "endpoints" in s:
            ep = s["endpoints"]
            lines += [
                f"🔗 Endpoints",
                f"  Private-Open   : {ep.get('private_open', 0)} ⚠️",
                f"  Public-Open    : {ep.get('public_open', 0)}",
                f"  Private-Closed : {ep.get('private_closed', 0)}",
                f"  Public-Closed  : {ep.get('public_closed', 0)}",
                f"",
            ]

        # Parameters
        if "parameters" in s:
            p = s["parameters"]
            lines += [
                f"🔑 Parameters : {p.get('total', 0)} ({p.get('sensitive', 0)} sensitive)",
            ]

        # Tech
        if s.get("tech"):
            lines += [f"", f"🛠️ Tech: {s['tech']}"]

        # Top findings
        top = s.get("top_findings", [])
        if top:
            lines += [f"", f"🔥 Top Findings:"]
            for url in top[:5]:
                lines.append(f"  • {url}")

        return "\n".join(lines)

    # =============================================================
    # DISCORD
    # =============================================================
    def _send_discord(self, text: str, summary: dict):
        """Kirim ke Discord via webhook dengan rich embed."""
        # Warna embed: merah kalau ada private-open (menarik), hijau kalau normal
        priv_open = summary.get("endpoints", {}).get("private_open", 0)
        color = 0xFF4444 if priv_open else 0x44FF44

        embed = {
            "title": f"🎯 ShadowPath - {summary.get('target', 'Scan')}",
            "description": f"Mode: **{summary.get('mode', '?').upper()}** · {summary.get('elapsed', '')}",
            "color": color,
            "fields": [],
        }

        # Subdomain field
        if "subdomains" in summary:
            sub = summary["subdomains"]
            embed["fields"].append({
                "name": "📡 Subdomains",
                "value": f"Total: {sub.get('total',0)} · Live: {sub.get('live',0)}",
                "inline": True,
            })

        # Endpoint field
        if "endpoints" in summary:
            ep = summary["endpoints"]
            embed["fields"].append({
                "name": "🔗 Endpoints",
                "value": (f"⚠️ Private-Open: **{ep.get('private_open',0)}**\n"
                          f"✅ Public-Open: {ep.get('public_open',0)}\n"
                          f"🔒 Private-Closed: {ep.get('private_closed',0)}"),
                "inline": True,
            })

        # Params field
        if "parameters" in summary:
            p = summary["parameters"]
            embed["fields"].append({
                "name": "🔑 Parameters",
                "value": f"{p.get('total',0)} total ({p.get('sensitive',0)} sensitive)",
                "inline": True,
            })

        # Tech field
        if summary.get("tech"):
            embed["fields"].append({
                "name": "🛠️ Technology",
                "value": summary["tech"][:1000],
                "inline": False,
            })

        # Top findings
        top = summary.get("top_findings", [])
        if top:
            findings = "\n".join(f"• {u}" for u in top[:5])
            embed["fields"].append({
                "name": "🔥 Top Findings",
                "value": findings[:1000],
                "inline": False,
            })

        payload = {"embeds": [embed], "username": "ShadowPath"}

        try:
            r = requests.post(self.discord_webhook, json=payload, timeout=10)
            if r.status_code in (200, 204):
                Logger.success("Notification sent to Discord")
            else:
                Logger.warn(f"Discord notification failed: {r.status_code}")
        except requests.RequestException as e:
            Logger.warn(f"Discord notification error: {e}")

    # =============================================================
    # TELEGRAM
    # =============================================================
    def _send_telegram(self, text: str):
        """Kirim ke Telegram via bot API."""
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            r = requests.post(url, json=payload, timeout=10)
            if r.status_code == 200:
                Logger.success("Notification sent to Telegram")
            else:
                Logger.warn(f"Telegram notification failed: {r.status_code} - {r.text[:100]}")
        except requests.RequestException as e:
            Logger.warn(f"Telegram notification error: {e}")

    def test_connection(self) -> bool:
        """Test kirim pesan sederhana untuk verifikasi konfigurasi."""
        if not self.enabled:
            Logger.warn("No notification channel configured")
            return False

        test_msg = "✅ ShadowPath notification test - connection OK"
        ok = False

        if self.discord_webhook:
            try:
                r = requests.post(self.discord_webhook,
                                 json={"content": test_msg, "username": "ShadowPath"},
                                 timeout=10)
                ok = r.status_code in (200, 204)
                Logger.success("Discord OK") if ok else Logger.warn(f"Discord failed: {r.status_code}")
            except requests.RequestException as e:
                Logger.warn(f"Discord test error: {e}")

        if self.telegram_token and self.telegram_chat_id:
            try:
                url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
                r = requests.post(url, json={"chat_id": self.telegram_chat_id, "text": test_msg}, timeout=10)
                ok = r.status_code == 200
                Logger.success("Telegram OK") if ok else Logger.warn(f"Telegram failed: {r.status_code}")
            except requests.RequestException as e:
                Logger.warn(f"Telegram test error: {e}")

        return ok
