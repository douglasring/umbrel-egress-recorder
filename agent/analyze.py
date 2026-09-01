"""Optional LLM analysis of a redacted report.

OFF unless an API key is configured. This is the only step that sends anything off
the node, and it reverses the project's default posture of keeping data local, so it
is opt-in rather than opt-out.

What is sent is the redacted report: the flagged endpoint, the pre-NAT container
address (RFC 1918, meaningless off this LAN), timing, volume and coverage. The
node's own LAN address and every unrelated peer are excluded before this is called.
"""

import json
import urllib.request

SYSTEM = (
    "You are helping a home Bitcoin/Lightning node operator triage a firewall alert. "
    "Be concise and concrete. Weigh the most likely benign explanations first - on an "
    "Umbrel, a reputation hit on a hosting IP is very often a Tor relay, since many "
    "apps egress via Tor and relays sit on low-reputation hosting. A reputation hit is "
    "not proof of malice. Only packet headers were captured, so you cannot know what "
    "was sent. State what the evidence supports, what it does not, and the single most "
    "useful next check. Do not speculate beyond the data."
)


def analyse(cfg, report_text):
    """Return analysis text, or None when disabled or unavailable."""
    provider = (cfg.get("LLM") or "none").lower()
    if provider == "none":
        return None

    prompt = "Triage this network egress report:\n\n" + report_text

    try:
        if provider == "anthropic":
            key = cfg.get("ANTHROPIC_API_KEY")
            if not key:
                return None
            body = json.dumps({
                "model": cfg.get("LLM_MODEL") or "claude-sonnet-5",
                "max_tokens": 700,
                "system": SYSTEM,
                "messages": [{"role": "user", "content": prompt}],
            }).encode()
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages", data=body, method="POST")
            req.add_header("x-api-key", key)
            req.add_header("anthropic-version", "2023-06-01")
            req.add_header("content-type", "application/json")
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            return "".join(b.get("text", "") for b in data.get("content", [])).strip()

        if provider == "openai":
            key = cfg.get("OPENAI_API_KEY")
            if not key:
                return None
            body = json.dumps({
                "model": cfg.get("LLM_MODEL") or "gpt-4o-mini",
                "messages": [{"role": "system", "content": SYSTEM},
                             {"role": "user", "content": prompt}],
            }).encode()
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions", data=body, method="POST")
            req.add_header("Authorization", "Bearer " + key)
            req.add_header("content-type", "application/json")
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            return data["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        # Analysis is an enhancement; never let it stop the notification.
        return "(analysis unavailable: %s)" % exc

    return None
