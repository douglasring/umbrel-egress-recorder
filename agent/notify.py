"""Notification sinks. Outbound HTTPS only; no inbound listener."""

import json
import urllib.parse
import urllib.request


def _post(url, data, headers=None, timeout=20):
    req = urllib.request.Request(url, data=data, method="POST")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


def send(cfg, title, body):
    """Deliver one notification. Returns a short status string for the log."""
    kind = (cfg.get("NOTIFY") or "none").lower()

    if kind == "none":
        return "notify disabled"

    if kind == "ntfy":
        topic = cfg.get("NTFY_TOPIC")
        if not topic:
            return "ntfy: NTFY_TOPIC not set"
        server = (cfg.get("NTFY_SERVER") or "https://ntfy.sh").rstrip("/")
        headers = {"Title": title, "Priority": "high", "Tags": "warning"}
        token = cfg.get("NTFY_TOKEN")
        if token:
            headers["Authorization"] = "Bearer " + token
        _post("%s/%s" % (server, topic), body.encode("utf-8"), headers)
        return "ntfy -> %s" % topic

    if kind == "telegram":
        tok, chat = cfg.get("TELEGRAM_TOKEN"), cfg.get("TELEGRAM_CHAT_ID")
        if not (tok and chat):
            return "telegram: TELEGRAM_TOKEN/TELEGRAM_CHAT_ID not set"
        payload = urllib.parse.urlencode({
            "chat_id": chat, "text": "*%s*\n\n%s" % (title, body),
            "parse_mode": "Markdown", "disable_web_page_preview": "true",
        }).encode()
        _post("https://api.telegram.org/bot%s/sendMessage" % tok, payload,
              {"Content-Type": "application/x-www-form-urlencoded"})
        return "telegram -> %s" % chat

    if kind == "webhook":
        url = cfg.get("WEBHOOK_URL")
        if not url:
            return "webhook: WEBHOOK_URL not set"
        _post(url, json.dumps({"title": title, "text": body}).encode(),
              {"Content-Type": "application/json"})
        return "webhook -> posted"

    return "unknown NOTIFY=%r" % kind
