"""Firewalla MSP API client - read-only.

Contract confirmed against https://docs.firewalla.net (api-reference/alarm,
api-reference/search, data-models/alarm):

  GET https://<msp-domain>/v2/alarms
    Authorization: Token <personal access token>
    query    search DSL, URL-encoded; qualifiers include ts, type, status, box.id,
             device.id, remote.category, remote.domain, remote.region
    sortBy   e.g. ts:asc          limit  <=500 (default 200)
    cursor   base64 continuation from a prior next_cursor
  -> { count, results[], next_cursor }

Alarm type 1 is "Security Activity". `remote` is present only for types
[1, 2, 8, 9, 10, 16]; note `remote.port` is an ARRAY of numbers, not a scalar.

Only GET is used. Firewalla warns that this API writes directly to live data, so
nothing here creates, modifies or archives anything.
"""

import json
import urllib.error
import urllib.parse
import urllib.request

# data-models/alarm.md#alarm-type
ALARM_TYPES = {
    1: "Security Activity", 2: "Abnormal Upload", 3: "Large Bandwidth Usage",
    4: "Monthly Data Plan", 5: "New Device", 6: "Device Back Online",
    7: "Device Offline", 8: "Video Activity", 9: "Gaming Activity",
    10: "Porn Activity", 11: "VPN Activity", 12: "VPN Connection Restored",
    13: "VPN Connection Error", 14: "Open Port",
    15: "Internet Connectivity Update", 16: "Large Upload",
}

# Types whose alarms carry a `remote` object, i.e. the ones we can attribute.
TYPES_WITH_REMOTE = (1, 2, 8, 9, 10, 16)


class MspError(Exception):
    pass


class Msp:
    def __init__(self, domain, token, timeout=30, opener=None):
        self.base = "https://%s/v2" % domain.strip().strip("/")
        self.token = token
        self.timeout = timeout
        self._opener = opener or urllib.request.urlopen

    def _get(self, path, params=None):
        url = self.base + path
        if params:
            # The docs are explicit that the query string must be URL encoded.
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={
            "Authorization": "Token " + self.token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        try:
            with self._opener(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")[:200]
            except Exception:
                pass
            if exc.code in (401, 403):
                raise MspError("MSP rejected the token (HTTP %d). Check MSP_TOKEN "
                               "and that the account has an API-capable plan." % exc.code)
            raise MspError("MSP GET %s failed: HTTP %d %s" % (path, exc.code, body))
        except Exception as exc:
            raise MspError("MSP GET %s failed: %s" % (path, exc))

    def boxes(self):
        return self._get("/boxes").get("results", [])

    def alarms(self, query, limit=200, max_pages=20):
        """All alarms matching `query`, oldest first, following next_cursor."""
        out, cursor, pages = [], None, 0
        while pages < max_pages:
            params = {"query": query, "sortBy": "ts:asc", "limit": limit}
            if cursor:
                params["cursor"] = cursor
            data = self._get("/alarms", params)
            out.extend(data.get("results") or [])
            cursor = data.get("next_cursor")
            pages += 1
            if not cursor:
                break
        return out

    def new_security_alarms(self, since_ts=None, types=(1,), active_only=True):
        """Incremental poll.

        `ts:>N` is what makes this safe: each poll asks only for alarms newer than
        the last one seen, so an alarm cannot be missed by mistiming a poll the way
        a fixed look-back window can. Without a ts qualifier the API defaults to the
        last 30 days, which is the right behaviour on a cold start.
        """
        terms = ["type:" + ",".join(str(t) for t in types)]
        if active_only:
            terms.append("status:active")
        if since_ts:
            # Fractional timestamps are supported (ts:1695196894.395-...).
            terms.append("ts:>%s" % repr(float(since_ts)))
        return self.alarms(" ".join(terms))


def extract(alarm):
    """Reduce a raw alarm to the fields the recorder can be queried with.

    Returns None when the alarm carries no remote host, which is normal for the
    types that describe the local network rather than a conversation with a peer.
    """
    remote = alarm.get("remote") or {}
    ip = remote.get("ip")
    if not ip:
        return None

    # data-models/alarm.md types `remote.port` as Number[]. Treating it as a scalar
    # silently drops every port after the first.
    ports = remote.get("port")
    if isinstance(ports, (int, float)):
        ports = [int(ports)]
    elif isinstance(ports, list):
        ports = [int(p) for p in ports if isinstance(p, (int, float))]
    else:
        ports = []

    device = alarm.get("device") or {}
    return {
        "aid": alarm.get("aid"),
        "gid": alarm.get("gid"),
        "ts": float(alarm.get("ts") or 0),
        "type": alarm.get("type"),
        "type_name": ALARM_TYPES.get(alarm.get("type"), str(alarm.get("type"))),
        "message": alarm.get("message") or "",
        "protocol": alarm.get("protocol"),
        "direction": alarm.get("direction"),
        "remote_ip": ip,
        "remote_ports": ports,
        "remote_domain": remote.get("domain") or remote.get("rootDomain"),
        "remote_region": remote.get("region"),
        "remote_category": remote.get("category"),
        "device_ip": device.get("ip"),
        "device_name": device.get("name"),
    }
