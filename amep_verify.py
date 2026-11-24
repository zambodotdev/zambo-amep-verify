#!/usr/bin/env python3
"""Independent AMEP verifier, written from the specification text only.

Implements: Section 10 evaluation over a single packet, Section 12.1
canonical form (RFC 8785 JCS) and well-formedness, Section 12.2 signing
with the exact Ed25519 acceptance rule, and verifier state input in the
shape Section 10.7 publishes (consumed as given; no state is built
across packets). No reference implementation source was read or used.

CLI (the shape the conformance README specifies):
    amep_verify.py PACKET.json --keys KEYS.json [--state STATE.json]
prints {"outcome": ..., "invariant": ...} for the packet verdict.
"""
import hashlib
import json
import re
import sys
import unicodedata
from decimal import Decimal
from fractions import Fraction

# ---------------------------------------------------------------- Ed25519
# Pure-Python Ed25519 verification: RFC 8032 verification equation plus
# the pre-rejections of spec Section 12.2 (exact acceptance rule).

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1, 1, 0)  # extended coordinates (X, Y, Z, T)


def _xrecover(y):
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if (x * x - xx) % _P != 0:
        return None
    return x


_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _xrecover(_BY)
if _BX & 1:
    _BX = _P - _BX
_BASE = (_BX, _BY, 1, _BX * _BY % _P)


def _pt_add(Pt, Qt):
    X1, Y1, Z1, T1 = Pt
    X2, Y2, Z2, T2 = Qt
    A = (Y1 - X1) * (Y2 - X2) % _P
    B = (Y1 + X1) * (Y2 + X2) % _P
    C = 2 * _D * T1 * T2 % _P
    Dd = 2 * Z1 * Z2 % _P
    E = B - A
    F = Dd - C
    G = Dd + C
    H = B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _pt_double(Pt):
    X1, Y1, Z1, _ = Pt
    A = X1 * X1 % _P
    B = Y1 * Y1 % _P
    C = 2 * Z1 * Z1 % _P
    Dd = (-A) % _P
    E = (X1 + Y1) * (X1 + Y1) - A - B
    E %= _P
    G = Dd + B
    F = G - C
    H = Dd - B
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _scalarmult(Pt, e):
    Q = _IDENTITY
    bits = bin(e)[2:]
    for bit in reversed(bits):
        pass
    # double-and-add, MSB first
    Q = _IDENTITY
    for bit in bin(e)[2:]:
        Q = _pt_double(Q)
        if bit == "1":
            Q = _pt_add(Q, Pt)
    return Q


def _pt_equal(Pt, Qt):
    X1, Y1, Z1, _ = Pt
    X2, Y2, Z2, _ = Qt
    return (X1 * Z2 - X2 * Z1) % _P == 0 and (Y1 * Z2 - Y2 * Z1) % _P == 0


def _pt_from_bytes(b):
    """Decode a 32-byte Ed25519 point encoding. Returns None when the
    encoding is non-canonical (y >= p) or not on the curve."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    sign = b[31] >> 7
    if y >= _P:
        return None
    x = _xrecover(y)
    if x is None:
        return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def _is_small_order(Pt):
    return _pt_equal(_scalarmult(Pt, 8), _IDENTITY)


def ed25519_verify(sig, msg, pub):
    """Strict verification per RFC 8032's equation and spec 12.2."""
    if len(sig) != 64 or len(pub) != 32:
        return False
    R = _pt_from_bytes(sig[:32])
    A = _pt_from_bytes(pub)
    if R is None or A is None:
        return False
    if _is_small_order(R) or _is_small_order(A):
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little")
    return _pt_equal(_scalarmult(_BASE, S), _pt_add(R, _scalarmult(A, h)))


# ------------------------------------------------------- ECMAScript numbers
def ecma_num(x):
    """Serialize a number exactly as ECMAScript Number.prototype.toString
    (and therefore RFC 8785) does."""
    if isinstance(x, bool):
        raise ValueError("not a number")
    if isinstance(x, int):
        return str(x)
    if x == 0:
        return "0"
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("non-finite number")
    sign = "-" if x < 0 else ""
    ax = abs(x)
    if ax == int(ax) and ax < 1e21:
        return sign + str(int(ax))
    d = Decimal(repr(ax))
    tup = d.as_tuple()
    digits = "".join(str(t) for t in tup.digits)
    exp = tup.exponent
    # value = int(digits) * 10**exp ; strip trailing zeros of the digit string
    stripped = digits.rstrip("0")
    exp += len(digits) - len(stripped)
    s = stripped if stripped else "0"
    k = len(s)
    n = exp + k
    if k <= n <= 21:
        return sign + s + "0" * (n - k)
    if 0 < n <= 21:
        return sign + s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + s
    e = n - 1
    esign = "+" if e >= 0 else "-"
    if k == 1:
        return sign + s + "e" + esign + str(abs(e))
    return sign + s[0] + "." + s[1:] + "e" + esign + str(abs(e))


# --------------------------------------------------------------------- JCS
def _jcs_string(s):
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif cp < 0x20 or 0xD800 <= cp <= 0xDFFF:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canon(obj):
    """RFC 8785 canonical form of a parsed JSON value, as UTF-8 bytes."""
    parts = []
    _canon(obj, parts)
    return "".join(parts).encode("utf-8", "surrogatepass")


def _canon(obj, parts):
    if obj is None:
        parts.append("null")
    elif obj is True:
        parts.append("true")
    elif obj is False:
        parts.append("false")
    elif isinstance(obj, str):
        parts.append(_jcs_string(obj))
    elif isinstance(obj, (int, float)):
        parts.append(ecma_num(obj))
    elif isinstance(obj, list):
        parts.append("[")
        for idx, item in enumerate(obj):
            if idx:
                parts.append(",")
            _canon(item, parts)
        parts.append("]")
    elif isinstance(obj, dict):
        parts.append("{")
        keys = sorted(obj.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        for idx, k in enumerate(keys):
            if idx:
                parts.append(",")
            parts.append(_jcs_string(k))
            parts.append(":")
            _canon(obj[k], parts)
        parts.append("}")
    else:
        raise ValueError("uncanonicalizable value %r" % (obj,))


def js_stringify(obj):
    """JSON.stringify equivalent (insertion order, ECMAScript numbers),
    used to mirror the harness path for object-form packets."""
    parts = []
    _js(obj, parts)
    return "".join(parts)


def _js(obj, parts):
    if obj is None:
        parts.append("null")
    elif obj is True:
        parts.append("true")
    elif obj is False:
        parts.append("false")
    elif isinstance(obj, str):
        parts.append(_jcs_string(obj))
    elif isinstance(obj, (int, float)):
        parts.append(ecma_num(obj))
    elif isinstance(obj, list):
        parts.append("[")
        for idx, item in enumerate(obj):
            if idx:
                parts.append(",")
            _js(item, parts)
        parts.append("]")
    elif isinstance(obj, dict):
        parts.append("{")
        for idx, (k, v) in enumerate(obj.items()):
            if idx:
                parts.append(",")
            parts.append(_jcs_string(k))
            parts.append(":")
            _js(v, parts)
        parts.append("}")
    else:
        raise ValueError("unserializable value %r" % (obj,))


# ------------------------------------------------------------ strict parser
class StrictParseError(Exception):
    pass


def _is_noncharacter(cp):
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


def _walk_checks(value, depth, issues):
    if depth > 32:
        issues.append("nesting exceeds 32 levels")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if len(k.encode("utf-8", "surrogatepass")) > 256:
                issues.append("member name exceeds 256 bytes")
            _string_checks(k, issues)
            _walk_checks(v, depth + 1, issues)
    elif isinstance(value, list):
        if len(value) > 4096:
            issues.append("array exceeds 4096 elements")
        for item in value:
            _walk_checks(item, depth + 1, issues)
    elif isinstance(value, str):
        _string_checks(value, issues)


def _string_checks(s, issues):
    if len(s.encode("utf-8", "surrogatepass")) > 8192:
        issues.append("string exceeds 8192 bytes")
    for ch in s:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            issues.append("lone surrogate in string")
            return
        if _is_noncharacter(cp):
            issues.append("noncharacter in string")
            return


def parse_strict(text):
    """Parse JSON text under spec 12.1's rules. Returns (value, issues);
    a non-empty issues list means the packet is malformed."""
    issues = []

    def _pairs(pairs):
        seen = set()
        for k, _v in pairs:
            if k in seen:
                issues.append("duplicate member name %r" % k)
            seen.add(k)
        return dict(pairs)

    def _int(lit):
        v = int(lit)
        if abs(v) > 2 ** 53 - 1:
            issues.append("number outside the safe range")
        return v

    def _float(lit):
        v = float(lit)
        if abs(v) > 2 ** 53 - 1:
            issues.append("number outside the safe range")
        try:
            if Decimal(lit) != Decimal(ecma_num(v)):
                issues.append("number literal differs from the double it denotes")
        except Exception:
            issues.append("unparsable number literal")
        return v

    def _const(name):
        issues.append("non-JSON constant %s" % name)
        return None

    dec = json.JSONDecoder(object_pairs_hook=_pairs, parse_int=_int,
                           parse_float=_float, parse_constant=_const)
    try:
        value = dec.decode(text)
    except Exception as exc:
        raise StrictParseError(str(exc))
    _walk_checks(value, 0, issues)
    return value, issues


def load_js_json(text):
    """Parse JSON the way ECMAScript JSON.parse does (every number a
    double, duplicate names last-wins). Used for harness-side files."""
    return json.loads(text, parse_int=lambda s: float(s),
                      parse_float=lambda s: float(s))


# --------------------------------------------------------------------- time
_RFC3339 = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")


def _days_from_civil(y, m, d):
    # Howard Hinnant's algorithm; days since 1970-01-01.
    y -= 1 if m <= 2 else 0
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m - 3 if m > 2 else m + 9) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _valid_date(y, m, d):
    if not (1 <= m <= 12):
        return False
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    mdays = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    return 1 <= d <= mdays[m - 1]


class Malformed(Exception):
    pass


def parse_time(value):
    """Spec 5.1.1 time: epoch seconds as a Fraction, or Malformed."""
    if isinstance(value, bool):
        raise Malformed("boolean is not a time")
    if isinstance(value, (int, float)):
        return Fraction(value).limit_denominator(10 ** 9)
    if isinstance(value, str):
        m = _RFC3339.match(value)
        if not m:
            raise Malformed("time string is not RFC 3339: %r" % value)
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        hh, mi, ss = int(m.group(4)), int(m.group(5)), int(m.group(6))
        if not _valid_date(y, mo, d) or hh > 23 or mi > 59 or ss > 59:
            raise Malformed("invalid RFC 3339 time: %r" % value)
        frac = Fraction(0)
        if m.group(7):
            digits = m.group(7)[1:]
            if len(digits) > 3:
                raise Malformed("time finer than milliseconds: %r" % value)
            frac = Fraction(int(digits.ljust(3, "0")), 1000)
        off = m.group(8)
        offset = 0
        if off not in ("Z", "z"):
            osign = 1 if off[0] == "+" else -1
            oh, om = int(off[1:3]), int(off[4:6])
            if oh > 23 or om > 59:
                raise Malformed("invalid RFC 3339 offset: %r" % value)
            offset = osign * (oh * 3600 + om * 60)
        days = _days_from_civil(y, mo, d)
        return Fraction(days * 86400 + hh * 3600 + mi * 60 + ss - offset) + frac
    raise Malformed("not a time: %r" % (value,))


def get_time(obj, field, required=True):
    if field not in obj or obj[field] is None:
        if required:
            raise Malformed("missing time %s" % field)
        return None
    return parse_time(obj[field])


# ------------------------------------------------------------- claim algebra
EFFECT_ORDER = ["read", "write_local", "write_shared", "external_send",
                "destructive", "financial"]
BASE_COST = {"read": 0, "write_local": 1, "write_shared": 3,
             "external_send": 5, "destructive": 10, "financial": 20}
DATA_MULT = {"public": 1, "internal": 1, "source": 1, "confidential": 2,
             "secret": 5, "phi": 5, "pci": 5}
PROTECTED_SEGMENTS = ["/.claude/", "/.codex/", "/.cursor/", "/.gemini/",
                      "/.git/hooks/", "/.ssh/authorized_keys"]
PROTECTED_NAMES = {"AGENTS.md", "CLAUDE.md", ".mcp.json", ".zshrc", ".bashrc"}
ROLES = {"mandate": {"issuer"}, "revocation": {"issuer"}, "status": {"issuer"},
         "delegation": {"issuer", "host"}, "intent": {"issuer", "host"},
         "interpretation": {"host"}, "invocation": {"host"},
         "decision": {"host"}, "effect": {"observer"},
         "approval": {"approver"}, "finding": {"host", "observer"},
         "call_statement": {"observer"}}
KNOWN_CLAIM_KEYS = {"actions", "resources", "grants", "data", "ceiling",
                    "exp", "nbf", "purpose", "deny_actions", "deny_resources",
                    "depth", "budget", "limits"}
KNOWN_LIMIT_KEYS = {"unit", "per_effect", "per_call", "per_period",
                    "period", "counted_by", "actions"}
FLOW_RE = re.compile(r"^[a-z_]+->[a-z_]+$")
AMOUNT_RE = re.compile(r"^(0|[1-9][0-9]{0,38})(\.[0-9]{1,18})?$")
UNIT_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}:[\x21-\x7e]{1,128}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")


def pat_match(pat, v):
    if not isinstance(pat, str) or not isinstance(v, str):
        return False
    return pat == "*" or (pat.endswith("*") and v.startswith(pat[:-1])) or pat == v


def pat_subsumed(c, p):
    if p == "*":
        return True
    if c == p:
        return True
    if p.endswith("*"):
        core = c[:-1] if c.endswith("*") else c
        return core.startswith(p[:-1])
    return False


def _is_str_list(v):
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def _as_int(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float) and v == int(v) and abs(v) < 2 ** 53:
        return int(v)
    return None


def _is_extension_key(k):
    return k.startswith("x-") or "." in k


def _parse_amount(s, what="amount"):
    if not isinstance(s, str) or not AMOUNT_RE.match(s):
        raise Malformed("%s does not match the amount grammar: %r" % (what, s))
    return Decimal(s)


def parse_limit(raw, version03):
    if not isinstance(raw, dict):
        raise Malformed("limit is not an object")
    if version03:
        for k in raw:
            if k not in KNOWN_LIMIT_KEYS and not _is_extension_key(k):
                raise Malformed("unknown limit member %s" % k)
    unit = raw.get("unit")
    if not isinstance(unit, str) or not UNIT_RE.match(unit):
        raise Malformed("limit unit malformed")
    lim = {"unit": unit, "per_effect": None, "per_call": None,
           "per_period": None, "period": None, "counted_by": None,
           "actions": None}
    for f in ("per_effect", "per_call", "per_period"):
        if raw.get(f) is not None:
            lim[f] = _parse_amount(raw[f], "limit " + f)
    if raw.get("period") is not None:
        p = _as_int(raw["period"])
        if p is None or p <= 0:
            raise Malformed("limit period malformed")
        lim["period"] = p
    if (lim["per_period"] is None) != (lim["period"] is None):
        raise Malformed("per_period and period must appear together")
    if raw.get("counted_by") is not None:
        if not isinstance(raw["counted_by"], str):
            raise Malformed("counted_by malformed")
        lim["counted_by"] = raw["counted_by"]
    if raw.get("actions") is not None:
        if not _is_str_list(raw["actions"]):
            raise Malformed("limit actions malformed")
        lim["actions"] = list(raw["actions"])
    return lim


def parse_claims(c, version03):
    """Parse a claim set (spec 5.3) into the internal form, or Malformed."""
    if not isinstance(c, dict):
        raise Malformed("claims is not an object")
    if version03:
        for k in c:
            if k not in KNOWN_CLAIM_KEYS and not _is_extension_key(k):
                raise Malformed("unknown claim member %s" % k)
    if "grants" in c:
        if not version03:
            raise Malformed("grants in a packet that is not amep_version 0.3")
        if "actions" in c or "resources" in c:
            raise Malformed("grants beside actions or resources")
        g = c["grants"]
        if not isinstance(g, list) or not g:
            raise Malformed("empty grants")
        grants = []
        for entry in g:
            if not isinstance(entry, dict) or set(entry.keys()) != {"actions", "resources"}:
                raise Malformed("grant is not exactly {actions, resources}")
            a, r = entry["actions"], entry["resources"]
            if not _is_str_list(a) or not a or not _is_str_list(r) or not r:
                raise Malformed("grant lists must be non-empty")
            grants.append({"actions": list(a), "resources": list(r)})
    else:
        a, r = c.get("actions"), c.get("resources")
        if not _is_str_list(a) or not _is_str_list(r):
            raise Malformed("claims carry neither grants nor actions/resources")
        grants = [{"actions": list(a), "resources": list(r)}]
    data = c.get("data")
    if data is None:
        data = []
    if not _is_str_list(data) or any(not FLOW_RE.match(f) for f in data):
        raise Malformed("data flows malformed")
    ceiling = c.get("ceiling")
    if ceiling not in EFFECT_ORDER:
        raise Malformed("ceiling malformed")
    if "exp" not in c:
        raise Malformed("claims exp missing")
    exp = parse_time(c["exp"])
    nbf = parse_time(c["nbf"]) if c.get("nbf") is not None else None
    purpose = c.get("purpose")
    if purpose is not None and not isinstance(purpose, str):
        raise Malformed("purpose malformed")
    deny_a = c.get("deny_actions")
    deny_r = c.get("deny_resources")
    if deny_a is None:
        deny_a = []
    if deny_r is None:
        deny_r = []
    if not _is_str_list(deny_a) or not _is_str_list(deny_r):
        raise Malformed("deny lists malformed")
    depth = c.get("depth")
    if depth is not None:
        depth = _as_int(depth)
        if depth is None or depth < 0:
            raise Malformed("depth malformed")
    budget = c.get("budget")
    if budget is not None:
        budget = _as_int(budget)
        if budget is None or budget < 0:
            raise Malformed("budget malformed")
    limits = []
    if c.get("limits") is not None:
        if not isinstance(c["limits"], list):
            raise Malformed("limits malformed")
        limits = [parse_limit(x, version03) for x in c["limits"]]
    return {"grants": grants, "data": set(data), "ceiling": ceiling,
            "exp": exp, "nbf": nbf, "purpose": purpose,
            "deny_actions": list(deny_a), "deny_resources": list(deny_r),
            "depth": depth, "budget": budget, "limits": limits}


def claims_subset(child, parent):
    """C_child is equal to or narrower than C_parent (spec 7.1)."""
    for gc in child["grants"]:
        ok = False
        for gp in parent["grants"]:
            if (all(any(pat_subsumed(a, pa) for pa in gp["actions"]) for a in gc["actions"])
                    and all(any(pat_subsumed(r, pr) for pr in gp["resources"]) for r in gc["resources"])):
                ok = True
                break
        if not ok:
            return False
    if not child["data"] <= parent["data"]:
        return False
    if EFFECT_ORDER.index(child["ceiling"]) > EFFECT_ORDER.index(parent["ceiling"]):
        return False
    if child["exp"] > parent["exp"]:
        return False
    if parent["nbf"] is not None and (child["nbf"] is None or child["nbf"] < parent["nbf"]):
        return False
    if parent["purpose"] is not None and child["purpose"] != parent["purpose"]:
        return False
    for dp in parent["deny_actions"]:
        if not any(pat_subsumed(dp, dc) for dc in child["deny_actions"]):
            return False
    for dp in parent["deny_resources"]:
        if not any(pat_subsumed(dp, dc) for dc in child["deny_resources"]):
            return False
    pd, cd = parent["depth"], child["depth"]
    if pd is not None:
        if pd == 0:
            return False
        if cd is None or cd >= pd:
            return False
    if parent["budget"] is not None:
        cb = child["budget"] if child["budget"] is not None else parent["budget"]
        if cb > parent["budget"]:
            return False
    for pl in parent["limits"]:
        for cl in child["limits"]:
            if cl["unit"] == pl["unit"] and set(cl["actions"] or []) == set(pl["actions"] or []):
                if (cl["per_call"] is not None and pl["per_call"] is not None
                        and cl["per_call"] > pl["per_call"]):
                    return False
                if (cl["per_period"] is not None and pl["per_period"] is not None
                        and cl["period"] == pl["period"]
                        and cl["per_period"] > pl["per_period"]):
                    return False
    return True


def claims_meet(c1, c2):
    grants = []
    for g1 in c1["grants"]:
        for g2 in c2["grants"]:
            acts = [p for p in g1["actions"]
                    if any(pat_subsumed(p, q) for q in g2["actions"])]
            res = [p for p in g1["resources"]
                   if any(pat_subsumed(p, q) for q in g2["resources"])]
            if acts and res:
                grants.append({"actions": acts, "resources": res})
    ceiling = c1["ceiling"] if EFFECT_ORDER.index(c1["ceiling"]) <= EFFECT_ORDER.index(c2["ceiling"]) else c2["ceiling"]
    exp = min(c1["exp"], c2["exp"])
    if c1["nbf"] is None:
        nbf = c2["nbf"]
    elif c2["nbf"] is None:
        nbf = c1["nbf"]
    else:
        nbf = max(c1["nbf"], c2["nbf"])
    return {"grants": grants, "data": c1["data"] & c2["data"],
            "ceiling": ceiling, "exp": exp, "nbf": nbf,
            "purpose": c1["purpose"] if c1["purpose"] is not None else c2["purpose"],
            "deny_actions": list(dict.fromkeys(c1["deny_actions"] + c2["deny_actions"])),
            "deny_resources": list(dict.fromkeys(c1["deny_resources"] + c2["deny_resources"])),
            "depth": None, "budget": None, "limits": []}


def satisfaction_fail(x, C, x_t):
    """Spec 7.4 in order. Returns None, 'scope' (I2) or 'released' (I5)."""
    granted = any(
        any(pat_match(p, x["action"]) for p in g["actions"])
        and any(pat_match(p, x["resource"]) for p in g["resources"])
        for g in C["grants"])
    if not granted:
        return "scope"
    if any(pat_match(p, x["action"]) for p in C["deny_actions"]):
        return "scope"
    if any(pat_match(p, x["resource"]) for p in C["deny_resources"]):
        return "scope"
    if EFFECT_ORDER.index(x["effect"]) > EFFECT_ORDER.index(C["ceiling"]):
        return "scope"
    for flow in x.get("released") or []:
        if flow not in C["data"]:
            return "released"
    if x_t > C["exp"]:
        return "scope"
    if C["nbf"] is not None and x_t < C["nbf"]:
        return "scope"
    return None


def parse_value(v):
    if not isinstance(v, dict):
        raise Malformed("value is not an object")
    amt = v.get("amount")
    unit = v.get("unit")
    if not isinstance(amt, str) or not AMOUNT_RE.match(amt):
        raise Malformed("value amount does not match the grammar")
    if not isinstance(unit, str) or not UNIT_RE.match(unit):
        raise Malformed("value unit does not match the grammar")
    if unit.startswith("caip19:") and "." in amt:
        raise Malformed("caip19 amount with a fractional part")
    return {"amount": Decimal(amt), "unit": unit,
            "period_spent": v.get("period_spent")}


def is_money_unit(unit):
    return unit.startswith("iso4217:") or unit.startswith("caip19:")


def is_protected(resource):
    if not isinstance(resource, str):
        return False
    for seg in PROTECTED_SEGMENTS:
        if seg in resource:
            return True
    return any(part in PROTECTED_NAMES for part in resource.split("/"))


def effect_cost(x):
    base = BASE_COST[x["effect"]]
    mult = 1
    for flow in x.get("released") or []:
        cls = flow.split("->")[0] if isinstance(flow, str) else ""
        mult = max(mult, DATA_MULT.get(cls, 1))
    if x["effect"] == "read" or (x.get("reversible") is True and x["effect"] != "external_send"):
        rev = 1
    else:
        rev = 3
    return base * mult * rev


def _identifier_clean(s):
    for ch in s:
        cp = ord(ch)
        if cp <= 0x1F or 0x7F <= cp <= 0x9F:
            return False
    return unicodedata.is_normalized("NFC", s)


def scan_identifiers(packet):
    """Spec 12.1: control characters or non-NFC in any action, resource or
    claim pattern anywhere in the packet makes the packet malformed."""
    bad = []

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("action", "resource") and isinstance(v, str):
                    if not _identifier_clean(v):
                        bad.append(k)
                if k in ("actions", "resources", "deny_actions", "deny_resources") and isinstance(v, list):
                    for item in v:
                        if isinstance(item, str) and not _identifier_clean(item):
                            bad.append(k)
                walk(v)
        elif isinstance(o, list):
            for item in o:
                walk(item)

    walk(packet)
    return bad


# ----------------------------------------------------------------- evaluator
def _result(rid, outcome, invariant, blame=None, gaps=None, reason=""):
    return {"id": rid, "outcome": outcome, "invariant": invariant,
            "blame": blame, "gaps": gaps or [], "reason": reason}


def _verdict(results):
    for outcome in ("violated", "unresolved"):
        for r in results:
            if r["outcome"] == outcome:
                return {"outcome": outcome, "invariant": r["invariant"],
                        "blame": r["blame"] if outcome == "violated" else None,
                        "gaps": r["gaps"] if outcome == "unresolved" else [],
                        "results": results}
    return {"outcome": "preserved", "invariant": "-", "blame": None,
            "gaps": [], "results": results}


class Evaluator:
    ARRAYS = ("mandates", "delegations", "intents", "interpretations",
              "invocations", "effects", "approvals", "revocations",
              "statuses", "findings", "decisions", "call_statements")

    def __init__(self, packet, keyset, state=None, malformed=False):
        self.packet = packet if isinstance(packet, dict) else {}
        self.keyset = keyset or {}
        self.version = self.packet.get("amep_version")
        self.version03 = self.version == "0.3"
        self.malformed = malformed
        if self.version is not None and self.version not in ("0.2", "0.3"):
            self.malformed = True
        self.by_id = {}
        self.invocations = []
        seen_ids = {}
        for arr in self.ARRAYS:
            items = self.packet.get(arr)
            if items is None:
                continue
            if not isinstance(items, list):
                self.malformed = True
                continue
            for obj in items:
                if not isinstance(obj, dict):
                    self.malformed = True
                    continue
                oid = obj.get("id")
                if isinstance(oid, str):
                    if oid in seen_ids:
                        self.malformed = True
                    seen_ids[oid] = obj
                    self.by_id[oid] = obj
                if arr == "invocations":
                    self.invocations.append(obj)
        if scan_identifiers(self.packet):
            self.malformed = True
        self.inv_positions = {}
        for idx, inv in enumerate(self.invocations):
            if isinstance(inv.get("id"), str):
                self.inv_positions[inv["id"]] = idx
        self.inv_digests = {}
        for inv in self.invocations:
            if isinstance(inv.get("id"), str):
                self.inv_digests[inv["id"]] = hashlib.sha256(canon(inv)).hexdigest()
        self.effects_by_inv = {}
        for e in self.packet.get("effects") or []:
            if isinstance(e, dict):
                self.effects_by_inv.setdefault(e.get("invocation"), []).append(e)
        self.verify_cache = {}
        self._claims_cache = {}
        self._carried = {}
        # verifier state (spec 10.7 shape), consumed as given
        state = state or {}
        self.approval_uses = {}
        for ap, val in (state.get("approvals_used") or {}).items():
            if isinstance(val, list) and len(val) == 2:
                self.approval_uses[ap] = (val[0], ((val[1], 1),))
        self.budget_running = {}
        for node_id, pts in (state.get("spent") or {}).items():
            v = _as_int(pts)
            if v is not None:
                self.budget_running[node_id] = v
        self.limit_totals = {}
        self.limit_state_keys = set()
        self.limit_anchored = set()
        for kstr, amt in (state.get("period_totals") or {}).items():
            parts = kstr.split("|")
            if len(parts) < 4:
                continue
            try:
                key = (parts[0], parts[1], int(parts[2]),
                       Fraction(Decimal(parts[3])),
                       parts[4] if len(parts) > 4 else "")
                self.limit_totals[key] = Decimal(amt)
                self.limit_state_keys.add(key)
            except Exception:
                continue
        digest_set = set(self.inv_digests.values())
        self.active_held = {}
        for dg, entry in (state.get("held") or {}).items():
            if dg not in digest_set and isinstance(entry, dict):
                self.active_held[dg] = entry
        self.approvals_held_active = {}
        self.state_bad_approvals = set()
        for ap, entry in (state.get("approvals_held") or {}).items():
            if (not isinstance(entry, dict)
                    or not isinstance(entry.get("invocation"), str)
                    or not isinstance(entry.get("digest"), str)):
                self.state_bad_approvals.add(ap)
                continue
            if entry["digest"] in digest_set:
                continue  # the packet decides that invocation afresh
            self.approvals_held_active[ap] = entry["invocation"]
        self.packet_holds = {}
        # quarantine: (packet position of the decision's invocation, finding id)
        self.quarantine = []
        for d in self.packet.get("decisions") or []:
            if not isinstance(d, dict):
                continue
            if d.get("mode") != "quarantine" or d.get("phase") != "pre_execution":
                continue
            st, _c = self.verify(d)
            if st != "ok":
                continue
            pos = self.inv_positions.get(d.get("invocation"))
            if pos is None:
                continue
            for fid in d.get("quarantined") or []:
                self.quarantine.append((pos, fid))

    # ------------------------------------------------------------- signatures
    def verify(self, obj):
        key = id(obj)
        if key in self.verify_cache:
            return self.verify_cache[key]
        out = self._verify(obj)
        self.verify_cache[key] = out
        return out

    def _verify(self, obj):
        """Returns (status, cause): status ok, or the 10.5.1 cause order:
        missing, unknown_key, role, invalid."""
        proof = obj.get("proof")
        if not isinstance(proof, dict):
            return ("missing", "missing")
        kid = proof.get("kid")
        if not isinstance(kid, str) or kid not in self.keyset:
            return ("unknown_key", "unknown_key")
        k = self.keyset[kid]
        roles = k.get("roles") or []
        permitted = ROLES.get(obj.get("kind"), set())
        if not any(r in permitted for r in roles):
            return ("role", "role")
        if k.get("revoked") is True:
            return ("invalid", "invalid")
        if proof.get("alg") != "Ed25519" or k.get("alg") != "Ed25519":
            return ("invalid", "invalid")
        x = k.get("x")
        sig = proof.get("sig")
        if not isinstance(x, str) or not HEX64.match(x):
            return ("invalid", "invalid")
        if not isinstance(sig, str) or not HEX128.match(sig):
            return ("invalid", "invalid")
        v = proof.get("v", 1)
        if v not in (1, 2):
            return ("invalid", "invalid")
        if self.version03 and v != 2:
            return ("invalid", "invalid")
        body = {kk: vv for kk, vv in obj.items() if kk != "proof"}
        msg = canon(body)
        if v == 2:
            kind = obj.get("kind") or ""
            msg = b"AMEP-v0.3\x00" + kind.encode("utf-8") + b"\x00" + msg
        ok = ed25519_verify(bytes.fromhex(sig), msg, bytes.fromhex(x))
        return ("ok", None) if ok else ("invalid", "invalid")

    def is_trusted_finding(self, fid):
        f = self.by_id.get(fid)
        if f is None or f.get("kind") != "finding":
            return False
        if f.get("integrity_label") != "trusted":
            return False
        st, _c = self.verify(f)
        return st == "ok"

    def claims_of(self, obj):
        key = id(obj)
        if key not in self._claims_cache:
            self._claims_cache[key] = parse_claims(obj.get("claims"), self.version03)
        return self._claims_cache[key]

    def carried_classes(self, iid):
        if iid in self._carried:
            return self._carried[iid]
        inv = self.by_id[iid]
        out = set()
        for e in self.effects_by_inv.get(iid, []):
            x = e.get("executed") or {}
            for c in x.get("accessed") or []:
                if isinstance(c, str):
                    out.add(c)
        for src in inv.get("derived_from") or []:
            tgt = self.by_id.get(src)
            if tgt is not None and tgt.get("kind") == "invocation":
                out |= self.carried_classes(src)
        self._carried[iid] = out
        return out

    def form_bodies(self, E):
        """Spec 10.2 step 14 tail: group receipts by observer and by body
        (compared without t and value.period_spent); a body occurs as
        often as the most any one observer recorded it."""
        groups = {}
        order = []
        for e in E:
            x = e.get("executed") or {}
            body = {k: v for k, v in x.items() if k != "t"}
            if isinstance(body.get("value"), dict):
                body["value"] = {k: v for k, v in body["value"].items()
                                 if k != "period_spent"}
            bk = canon(body)
            if bk not in groups:
                groups[bk] = {"x": x, "by_observer": {}, "receipts": []}
                order.append(bk)
            g = groups[bk]
            obs = e.get("observed_by")
            g["by_observer"][obs] = g["by_observer"].get(obs, 0) + 1
            g["receipts"].append(e)
        return [{"x": groups[bk]["x"],
                 "count": max(groups[bk]["by_observer"].values()),
                 "receipts": groups[bk]["receipts"]} for bk in order]

    # ------------------------------------------------------------- main entry
    def evaluate(self):
        if self.malformed:
            results = [_result(inv.get("id", "-"), "unresolved", "I7", None,
                               [{"need": "well_formed_packet", "ref": "-"}],
                               "packet malformed")
                       for inv in self.invocations]
            if not results:
                results = [_result("-", "unresolved", "I7", None,
                                   [{"need": "well_formed_packet", "ref": "-"}],
                                   "packet malformed")]
            return _verdict(results)
        results = []
        for idx, inv in enumerate(self.invocations):
            results.append(self.eval_invocation(inv, idx))
        # Section 10.3 decision reconciliation
        by_result = {r["id"]: r for r in results}
        for d in self.packet.get("decisions") or []:
            if not isinstance(d, dict):
                continue
            if d.get("mode") not in ("deny", "hold") or d.get("phase") != "pre_execution":
                continue
            st, _c = self.verify(d)
            if st != "ok":
                continue
            tgt = d.get("invocation")
            if tgt not in by_result:
                continue
            r = by_result[tgt]
            has_effect = tgt in self.effects_by_inv
            if has_effect:
                if r["outcome"] != "violated":
                    r.update({"outcome": "violated", "invariant": "I11",
                              "blame": "host", "gaps": [],
                              "reason": "effect despite deny"})
            else:
                enf = d.get("enforcement") or {}
                decl = (self.by_id.get(tgt) or {}).get("declared") or {}
                if ((enf.get("fail_mode") == "closed" or enf.get("applied") == "confirmed")
                        and decl.get("effect") in EFFECT_ORDER
                        and EFFECT_ORDER.index(decl["effect"]) >= EFFECT_ORDER.index("write_shared")
                        and r["outcome"] == "unresolved"):
                    r.update({"outcome": "unresolved", "invariant": "I10",
                              "blame": None,
                              "gaps": [{"need": "independent_observer", "ref": tgt}],
                              "reason": "a deny cannot settle that nothing executed"})
        # Section 10.4 orphan effects
        inv_ids = {inv.get("id") for inv in self.invocations}
        for e in self.packet.get("effects") or []:
            if isinstance(e, dict) and e.get("invocation") not in inv_ids:
                results.append(_result(e.get("id", "-"), "violated", "I11",
                                       "host", [], "bypass"))
        return _verdict(results)


# ------------------------------------------------- Section 10.2 (per invocation)
def _eval_invocation(self, inv, idx):
    iid = inv.get("id")

    def R(outcome, invariant, blame=None, gaps=None, reason=""):
        return _result(iid, outcome, invariant, blame, gaps, reason)

    def I7(gaps, reason):
        return R("unresolved", "I7", None, gaps, reason)

    influenced = inv.get("influenced_by")
    if influenced is None:
        influenced = []
    if not isinstance(influenced, list):
        return I7([{"need": "well_formed_evidence", "ref": iid}],
                  "influenced_by is not a list")
    # Quarantine check (before step 1)
    if inv.get("principal_confirmed") is not True:
        for (pos, fid) in self.quarantine:
            if idx > pos and fid in influenced:
                return R("violated", "I4", "host", [],
                         "quarantined content reached the agent")
    # Step 1: resolve chain
    auth = inv.get("authority_ref")
    cur = self.by_id.get(auth) if isinstance(auth, str) else None
    if cur is None or cur.get("kind") not in ("mandate", "delegation"):
        return I7([{"need": "root_mandate", "ref": "-"}], "no root mandate")
    chain = []
    seen = set()
    root_ok = False
    while True:
        if cur.get("id") in seen:
            break
        seen.add(cur.get("id"))
        chain.append(cur)
        if cur.get("kind") == "mandate":
            root_ok = True
            break
        parent = cur.get("parent")
        nxt = self.by_id.get(parent) if isinstance(parent, str) else None
        if nxt is None or nxt.get("kind") not in ("mandate", "delegation"):
            break
        cur = nxt
    if not root_ok:
        return I7([{"need": "root_mandate", "ref": "-"}], "no root mandate")
    # Step 2: intent exists; chain, invocation, interpretation, intent verified
    intent = None
    if inv.get("intent_ref") is not None:
        intent = self.by_id.get(inv["intent_ref"])
        if intent is None or intent.get("kind") != "intent":
            return I7([{"need": "intent", "ref": str(inv.get("intent_ref"))}],
                      "cited intent is missing")
    interp = None
    if isinstance(inv.get("interpretation_ref"), str):
        cand = self.by_id.get(inv["interpretation_ref"])
        if cand is not None and cand.get("kind") == "interpretation":
            interp = cand
    for obj in chain + [inv] + ([interp] if interp else []) + ([intent] if intent else []):
        st, cause = self.verify(obj)
        if st != "ok":
            return I7([{"need": "signature", "ref": obj.get("id", "-"),
                        "cause": cause}],
                      "signature refused (%s)" % st)
    # Section 10.6: derived_from must name earlier invocations
    derived = inv.get("derived_from")
    if derived is not None:
        if not isinstance(derived, list):
            return I7([{"need": "well_formed_evidence", "ref": iid}],
                      "derived_from is not a list")
        for src in derived:
            tgt = self.by_id.get(src)
            if (tgt is None or tgt.get("kind") != "invocation"
                    or self.inv_positions.get(src, 1 << 30) >= idx):
                return I7([{"need": "lineage", "ref": str(src)}],
                          "derived_from does not name an earlier invocation")
    # A malformed reserve makes the invocation's own evidence unusable (5.8)
    if inv.get("reserve") is not None:
        rsv = inv["reserve"]
        try:
            if not isinstance(rsv, dict):
                raise Malformed("reserve is not an object")
            _parse_amount(rsv.get("amount"), "reserve amount")
            if not isinstance(rsv.get("unit"), str) or not UNIT_RE.match(rsv["unit"]):
                raise Malformed("reserve unit malformed")
        except Malformed as m:
            return I7([{"need": "reserve", "ref": iid}], str(m))
    # Step 3: interpretation approved
    if interp is None:
        return R("unresolved", "I3", None,
                 [{"need": "interpretation", "ref": "-"}], "no interpretation")
    if interp.get("source") not in ("curated", "customer"):
        return R("unresolved", "I3", None,
                 [{"need": "interpretation", "ref": interp.get("id", "-")}],
                 "interpretation source is not approved")
    # Step 4: pinned adapters
    pins = self.packet.get("pinned_adapters")
    if isinstance(pins, dict) and pins:
        if pins.get(interp.get("adapter")) != interp.get("version"):
            return R("unresolved", "I3", None,
                     [{"need": "interpretation_pin", "ref": interp.get("id", "-")}],
                     "adapter version does not match the pin")
    # Step 5: attenuation (claims are first needed here)
    try:
        chain_claims = [self.claims_of(o) for o in chain]
        intent_claims = self.claims_of(intent) if intent else None
    except Malformed as m:
        return I7([{"need": "well_formed_evidence", "ref": "-"}], str(m))
    for child_c, parent_c in zip(chain_claims, chain_claims[1:]):
        if not claims_subset(child_c, parent_c):
            return R("violated", "I1", "delegator", [],
                     "a delegation widens its parent")
    # Step 6: liveness (5.12, with v0.3 effect times and propagation window)
    E = [e for e in self.packet.get("effects") or []
         if isinstance(e, dict) and e.get("invocation") == iid]
    try:
        i_t = get_time(inv, "t")
        eff_times = []
        for e in E:
            xb = e.get("executed")
            if not isinstance(xb, dict):
                raise Malformed("executed body missing")
            eff_times.append(get_time(xb, "t"))
    except Malformed as m:
        return I7([{"need": "well_formed_evidence", "ref": iid}], str(m))
    times = [i_t] + eff_times
    chain_ids = {o.get("id") for o in chain}
    rev_events = []
    unverified_rev_cause = None
    for rv in self.packet.get("revocations") or []:
        if not isinstance(rv, dict) or rv.get("target") not in chain_ids:
            continue
        st, cause = self.verify(rv)
        if st == "ok":
            try:
                rt = get_time(rv, "t")
            except Malformed as m:
                return I7([{"need": "well_formed_evidence", "ref": "-"}], str(m))
            rev_events.append((rt, self.by_id[rv["target"]]))
        elif unverified_rev_cause is None:
            unverified_rev_cause = cause
    status_by_target = {}
    for s in self.packet.get("statuses") or []:
        if not isinstance(s, dict) or s.get("target") not in chain_ids:
            continue
        st, _c = self.verify(s)
        if st != "ok":
            continue
        status_by_target.setdefault(s["target"], []).append(s)
        if s.get("revoked_at") is not None:
            try:
                rt = parse_time(s["revoked_at"])
            except Malformed as m:
                return I7([{"need": "well_formed_evidence", "ref": "-"}], str(m))
            rev_events.append((rt, self.by_id[s["target"]]))
    in_window = False
    for (rt, node) in rev_events:
        window = Fraction(0)
        rev = node.get("revocation")
        if isinstance(rev, dict) and rev.get("window") is not None:
            w = rev["window"]
            if isinstance(w, bool) or not isinstance(w, (int, float)) or w < 0:
                return I7([{"need": "well_formed_evidence", "ref": "-"}],
                          "revocation window malformed")
            window = Fraction(w).limit_denominator(10 ** 9)
        for tp in times:
            if rt <= tp:
                if tp >= rt + window:
                    return R("violated", "I6", "agent", [],
                             "acted under revoked authority")
                in_window = True
    if in_window:
        return R("unresolved", "I6", None,
                 [{"need": "revocation_settled", "ref": "-"}],
                 "revocation inside its propagation window")
    if unverified_rev_cause is not None:
        return I7([{"need": "revocation_signature", "ref": "-",
                    "cause": unverified_rev_cause}],
                  "an unverifiable revocation targets the chain")
    max_t = max(times)
    for node in chain:
        rev = node.get("revocation")
        if isinstance(rev, dict) and rev.get("status_ref"):
            fresh = False
            for s in status_by_target.get(node.get("id"), []):
                try:
                    ao = get_time(s, "as_of")
                except Malformed:
                    continue
                if ao >= max_t:
                    fresh = True
            if not fresh:
                return I7([{"need": "revocation_status",
                            "ref": node.get("id", "-")}],
                          "no fresh signed revocation status")
    # Step 7: declared target protected (I9)
    declared = inv.get("declared")
    if (not isinstance(declared, dict)
            or not isinstance(declared.get("action"), str)
            or not isinstance(declared.get("resource"), str)
            or declared.get("effect") not in EFFECT_ORDER):
        return I7([{"need": "well_formed_evidence", "ref": iid}],
                  "declared effect malformed")
    if is_protected(declared["resource"]):
        return R("violated", "I9", "agent", [],
                 "declared target is a protected resource")
    # Step 9: influence (I4)
    if influenced and inv.get("principal_confirmed") is not True \
            and declared["effect"] != "read":
        if any(not self.is_trusted_finding(fid) for fid in influenced):
            if E:
                return R("violated", "I4", "agent", [],
                         "untrusted influence on an executed call")
            return R("unresolved", "I4", None,
                     [{"need": "principal_confirmation", "ref": iid}],
                     "untrusted influence, not executed")
    # Section 5.14 call statements, before the receipts are checked
    stmts = [s for s in self.packet.get("call_statements") or []
             if isinstance(s, dict) and s.get("invocation") == iid]
    inv_digest = self.inv_digests.get(iid)
    for s in stmts:
        st, cause = self.verify(s)
        bad = st != "ok"
        disp = s.get("disposition")
        ec = s.get("effect_count")
        if disp not in ("completed", "not_executed", "failed_after_effects"):
            bad = True
        if not isinstance(ec, int) or isinstance(ec, bool) or ec < 0:
            bad = True
        if disp == "not_executed" and ec != 0:
            bad = True
        if not isinstance(s.get("observed_by"), str):
            bad = True
        try:
            get_time(s, "t")
        except Malformed:
            bad = True
        if bad:
            gaps = ([{"need": "call_statement_signature",
                      "ref": s.get("id", "-"), "cause": cause}]
                    if st != "ok" else
                    [{"need": "call_statement", "ref": s.get("id", "-")}])
            return I7(gaps, "a call statement is not usable evidence")
        if s.get("invocation_digest") is not None \
                and s["invocation_digest"] != inv_digest:
            return I7([{"need": "call_statement_binding",
                        "ref": s.get("id", "-")}],
                      "statement bound to another invocation")
        if inv.get("args_digest") is not None \
                and s.get("args_digest") is not None \
                and s["args_digest"] != inv["args_digest"]:
            if disp == "not_executed":
                return I7([{"need": "unaltered_call", "ref": s.get("id", "-")}],
                          "the call was altered and not executed")
            return R("violated", "I2", "transport", [],
                     "the call was altered in transit")
    for e in E:
        if e.get("invocation_digest") is not None \
                and e["invocation_digest"] != inv_digest:
            return I7([{"need": "receipt_binding", "ref": e.get("id", "-")}],
                      "receipt bound to another invocation")
    # Step 10: no effect receipt
    if not E:
        ne = [s for s in stmts if s.get("disposition") == "not_executed"]
        if ne:
            if EFFECT_ORDER.index(declared["effect"]) >= EFFECT_ORDER.index("write_shared"):
                s = ne[0]
                if inv.get("actor") is not None \
                        and s.get("observed_by") == inv["actor"]:
                    return R("unresolved", "I10", None,
                             [{"need": "independent_observer", "ref": iid}],
                             "not_executed stated by the actor")
                sk = self.keyset.get((s.get("proof") or {}).get("kid"), {})
                ik = self.keyset.get((inv.get("proof") or {}).get("kid"), {})
                if sk.get("operator") and ik.get("operator") \
                        and sk["operator"] == ik["operator"]:
                    return R("unresolved", "I10", None,
                             [{"need": "independent_observer", "ref": iid}],
                             "the observer shares the host's operator")
            return R("preserved", "-", None, [], "provably not executed")
        if isinstance(inv.get("approval_ref"), str):
            self.packet_holds[inv["approval_ref"]] = iid
        return I7([{"need": "receipt", "ref": iid}], "no effect receipt")
    for s in stmts:
        if s.get("disposition") == "not_executed":
            return R("violated", "I11", "server", [],
                     "receipts contradict a not_executed statement")
    for s in stmts:
        cnt = sum(1 for e in E if e.get("observed_by") == s.get("observed_by"))
        if cnt > s["effect_count"]:
            return R("violated", "I7", "server", [],
                     "more receipts than the statement counts")
        if cnt < s["effect_count"]:
            return I7([{"need": "receipt", "ref": iid}],
                      "a receipt was lost or withheld")
    # Steps 11-14, per receipt. Effective claims (7.3): the meet keeps the
    # patterns of the narrower (later) set that the wider set subsumes, so
    # the fold runs from the root with each next set as the meet's C1.
    eff_claims = chain_claims[-1]
    for c in reversed(chain_claims[:-1]):
        eff_claims = claims_meet(c, eff_claims)
    if intent_claims is not None:
        eff_claims = claims_meet(intent_claims, eff_claims)
    carried = self.carried_classes(iid)
    for e in E:
        if not isinstance(e.get("observed_by"), str) or not e["observed_by"]:
            return I7([{"need": "receipt_observer",
                        "ref": e.get("id", "-")}],
                      "a receipt names no observer")
        if e.get("assurance") not in ("L0", "L1", "L2", "L3"):
            return I7([{"need": "well_formed_evidence",
                        "ref": e.get("id", "-")}], "assurance malformed")
        st, cause = self.verify(e)
        if st != "ok":
            return I7([{"need": "receipt_signature",
                        "ref": e.get("id", "-"), "cause": cause}],
                      "receipt signature refused (%s)" % st)
        x = e.get("executed")
        if (not isinstance(x, dict)
                or not isinstance(x.get("action"), str)
                or not isinstance(x.get("resource"), str)
                or x.get("effect") not in EFFECT_ORDER):
            return I7([{"need": "well_formed_evidence",
                        "ref": e.get("id", "-")}], "executed body malformed")
        try:
            x_t = get_time(x, "t")
        except Malformed as m:
            return I7([{"need": "well_formed_evidence",
                        "ref": e.get("id", "-")}], str(m))
        # Step 12: observer independence
        if EFFECT_ORDER.index(declared["effect"]) >= EFFECT_ORDER.index("write_shared"):
            if inv.get("actor") is None:
                return R("unresolved", "I10", None,
                         [{"need": "actor", "ref": iid}], "no actor named")
            if e.get("observed_by") == inv["actor"] or e.get("assurance") == "L0":
                return R("unresolved", "I10", None,
                         [{"need": "independent_observer", "ref": iid}],
                         "the observer is the actor, or self-reported")
            ek = self.keyset.get((e.get("proof") or {}).get("kid"), {})
            ik = self.keyset.get((inv.get("proof") or {}).get("kid"), {})
            if ek.get("operator") and ik.get("operator") \
                    and ek["operator"] == ik["operator"]:
                return R("unresolved", "I10", None,
                         [{"need": "independent_observer", "ref": iid}],
                         "the observer shares the host's operator")
        # Step 13: declared / mediated comparison, executed protected
        if inv.get("mediated") is not None:
            if canon(x) != canon(inv["mediated"]):
                return R("violated", "I2", "server", [],
                         "executed differs from the mediated effect")
        else:
            if x["action"] != declared["action"] \
                    or x["resource"] != declared["resource"]:
                return R("violated", "I2", "server", [],
                         "executed differs from the declared effect")
        if is_protected(x["resource"]):
            return R("violated", "I9", "agent", [],
                     "executed against a protected resource")
        # Step 14: satisfaction, then lineage (10.6)
        fail = satisfaction_fail(x, eff_claims, x_t)
        if fail == "released":
            return R("violated", "I5", "agent", [],
                     "a released data flow is not permitted")
        if fail:
            return R("violated", "I2", "agent", [],
                     "the effect is outside the effective claims")
        recip = x.get("recipient")
        if isinstance(recip, str):
            classes = set(x.get("accessed") or []) | carried
            for d in classes:
                if "%s->%s" % (d, recip) not in eff_claims["data"]:
                    return R("violated", "I5", "agent", [],
                             "carried data reached an unpermitted recipient")
    # Bodies B (step 14 tail), value grammar, step 15 approvals
    B = self.form_bodies(E)
    for b in B:
        if b["x"].get("value") is not None:
            try:
                b["value"] = parse_value(b["x"]["value"])
            except Malformed as m:
                return I7([{"need": "value", "ref": iid}], str(m))
        else:
            b["value"] = None
    approval_passed = False
    if inv.get("approval_ref") is not None:
        aref = inv["approval_ref"]
        a = self.by_id.get(aref) if isinstance(aref, str) else None
        if a is None or a.get("kind") != "approval":
            return I7([{"need": "approval", "ref": str(aref)}],
                      "cited approval is missing")
        if a.get("id") in self.state_bad_approvals:
            return I7([{"need": "approval", "ref": a.get("id", "-")}],
                      "malformed approval hold in verifier state")
        st, cause = self.verify(a)
        if st != "ok":
            return I7([{"need": "signature", "ref": a.get("id", "-"),
                        "cause": cause}], "approval signature refused (%s)" % st)
        single = a.get("effect_digest")
        multi = a.get("effect_digests")
        if (single is None) == (multi is None):
            return I7([{"need": "well_formed_evidence", "ref": a.get("id", "-")}],
                      "an approval carries exactly one digest form")
        if single is not None and (not isinstance(single, str) or not HEX64.match(single)):
            return I7([{"need": "well_formed_evidence", "ref": a.get("id", "-")}],
                      "effect_digest malformed")
        if multi is not None and (not isinstance(multi, list) or not multi
                                  or any(not isinstance(d, str) or not HEX64.match(d)
                                         for d in multi)):
            return I7([{"need": "well_formed_evidence", "ref": a.get("id", "-")}],
                      "effect_digests malformed")
        if a.get("consumed") is True:
            return R("violated", "I8", "agent", [], "approval already consumed")
        digests = []
        for b in B:
            body = {k: v for k, v in b["x"].items() if k != "t"}
            if isinstance(body.get("value"), dict):
                body["value"] = {k: v for k, v in body["value"].items()
                                 if k != "period_spent"}
            digests.append(hashlib.sha256(canon(body)).hexdigest())
        for b, dg in zip(B, digests):
            if single is not None:
                if single != dg:
                    return R("violated", "I8", "agent", [],
                             "approval is not bound to the executed effect")
                if b["count"] > 1:
                    return R("violated", "I8", "agent", [],
                             "one approval, the approved body executed "
                             "more than once")
            elif multi.count(dg) < b["count"]:
                return R("violated", "I8", "agent", [],
                         "an effect was executed more often than approved")
            try:
                if a.get("expiry") is not None \
                        and parse_time(a["expiry"]) < max(i_t, get_time(b["x"], "t")):
                    return R("violated", "I8", "agent", [],
                             "approval used after its expiry")
                if a.get("nbf") is not None and parse_time(a["nbf"]) > i_t:
                    return R("violated", "I8", "agent", [],
                             "approval used before its nbf")
            except Malformed as m:
                return I7([{"need": "well_formed_evidence",
                            "ref": a.get("id", "-")}], str(m))
        use_key = (iid, tuple(sorted((dg, b["count"])
                                      for b, dg in zip(B, digests))))
        prior = self.approval_uses.get(a.get("id"))
        if prior is not None and prior != use_key:
            return R("violated", "I8", "agent", [],
                     "approval already used for another invocation or body")
        holder = self.approvals_held_active.get(a.get("id"))
        if a.get("id") in self.packet_holds:
            holder = self.packet_holds[a["id"]]
        if holder is not None and holder != iid:
            return I7([{"need": "held_outcome", "ref": holder}],
                      "the approval is held for an invocation whose outcome "
                      "is unknown")
        approval_passed = True
        self.approval_uses[a.get("id")] = use_key
    # Limits (7.6), then risk budget (step 16, Section 9.2)
    lim = self._eval_limits(inv, B, chain, chain_claims, intent_claims,
                            approval_passed, R, I7)
    if lim is not None and lim["outcome"] == "violated":
        return lim
    bud = self._eval_budget(inv, B, chain, R)
    if bud is not None:
        return bud
    if lim is not None:
        return lim
    return R("preserved", "-", None, [], "")


def _limit_applies(L, x):
    if L["actions"] is not None:
        return any(pat_match(p, x["action"]) for p in L["actions"])
    return x["effect"] == "financial"


def _eval_limits(self, inv, B, chain, chain_claims, intent_claims,
                 approval_passed, R, I7):
    nodes = list(zip(chain, chain_claims))
    if intent_claims is not None:
        nodes.append((self.by_id[inv["intent_ref"]], intent_claims))
    violated = None
    unresolved = None
    for b in B:
        x = b["x"]
        val = b["value"]
        for (node, claims) in nodes:
            limits = claims["limits"]
            if not limits:
                continue
            applicable = [L for L in limits if _limit_applies(L, x)]
            if not applicable:
                continue
            if val is None:
                if unresolved is None:
                    unresolved = I7([{"need": "value", "ref": inv.get("id")}],
                                    "an effect under a limit carries no value")
                continue
            same_unit = [L for L in applicable if L["unit"] == val["unit"]]
            if not same_unit:
                if x["effect"] == "financial" or is_money_unit(val["unit"]):
                    if violated is None:
                        violated = R("violated", "I2", "agent", [],
                                     "the effect's unit is not authorized")
                elif unresolved is None:
                    unresolved = I7([{"need": "value", "ref": inv.get("id")}],
                                    "no applicable limit has the effect's unit")
                continue
            for L in same_unit:
                if L["per_effect"] is not None \
                        and val["amount"] > L["per_effect"] \
                        and not approval_passed:
                    if violated is None:
                        violated = R("violated", "I2", "agent", [],
                                     "per-effect limit exceeded")
                if L["per_call"] is not None:
                    tot = Decimal(0)
                    for b2 in B:
                        if b2["value"] is not None \
                                and b2["value"]["unit"] == L["unit"] \
                                and _limit_applies(L, b2["x"]):
                            tot += b2["value"]["amount"] * b2["count"]
                    if tot > L["per_call"] and not approval_passed:
                        if violated is None:
                            violated = R("violated", "I2", "agent", [],
                                         "per-call limit exceeded")
                if L["per_period"] is not None:
                    res = self._check_period(inv, b, L, node, claims,
                                             approval_passed, R, I7)
                    if res is not None:
                        if res["outcome"] == "violated" and violated is None:
                            violated = res
                        elif res["outcome"] == "unresolved" and unresolved is None:
                            unresolved = res
    return violated if violated is not None else unresolved


def _check_period(self, inv, b, L, node, claims, approval_passed, R, I7):
    x = b["x"]
    val = b["value"]
    x_t = get_time(x, "t")
    nbf = claims["nbf"] if claims["nbf"] is not None else Fraction(0)
    period = L["period"]
    w = nbf + ((x_t - nbf) // period) * period
    akey = ",".join(L["actions"]) if L["actions"] else ""
    key = (node.get("id"), L["unit"], period, w, akey)
    amt = val["amount"] * b["count"]
    prev = self.limit_totals.get(key)
    incl = (prev if prev is not None else Decimal(0)) + amt
    F = None
    if L["counted_by"] is not None:
        for r in b["receipts"]:
            if r.get("observed_by") != L["counted_by"]:
                continue
            ps = (r.get("executed") or {}).get("value")
            if not isinstance(ps, dict):
                continue
            psm = ps.get("period_spent")
            if not isinstance(psm, dict):
                continue
            entry = psm.get(str(period))
            if isinstance(entry, dict) and "from" in entry and "total" in entry:
                try:
                    frm = entry["from"]
                    frm = frm if isinstance(frm, Fraction) else parse_time(frm) \
                        if isinstance(frm, str) else Fraction(frm)
                    if frm == w and isinstance(entry["total"], str):
                        F = Decimal(entry["total"])
                except Exception:
                    F = None
            if F is not None:
                break
    result = None
    total = incl
    if F is not None and F < incl:
        result = R("violated", "I7", "server", [],
                   "the counting observer's total is inconsistent")
    else:
        if F is not None:
            total = F
            self.limit_anchored.add(key)
        # A window total is known when verifier state seeded it, or when
        # the counting observer's own figure has anchored it in this
        # packet (7.6 rules 4-5). A figure from any other observer, or
        # in-packet accumulation alone, never makes it known.
        known = F is not None or key in self.limit_state_keys \
            or key in self.limit_anchored
        if not known:
            result = I7([{"need": "period_total", "ref": node.get("id")}],
                        "no period total from a counting observer or "
                        "earlier state for this window")
        elif total > L["per_period"] and not approval_passed:
            result = R("violated", "I2", "agent", [],
                       "period limit exceeded")
        else:
            wstr = str(int(w)) if w.denominator == 1 else str(float(w))
            keystr = "%s|%s|%s|%s" % (node.get("id"), L["unit"], period, wstr)
            if akey:
                keystr += "|" + akey
            hold_sum = Decimal(0)
            hold_unknown = False
            hold_ref = "-"
            for entry in self.active_held.values():
                amounts = entry.get("amounts") or {}
                if keystr in amounts:
                    hold_ref = entry.get("invocation", "-")
                    if amounts[keystr] is None:
                        hold_unknown = True
                    else:
                        try:
                            hold_sum += Decimal(amounts[keystr])
                        except Exception:
                            hold_unknown = True
            if (hold_unknown or hold_sum > 0) and not approval_passed \
                    and (hold_unknown or total + hold_sum > L["per_period"]):
                result = I7([{"need": "held_outcome", "ref": hold_ref}],
                            "an earlier call with an unknown outcome is "
                            "held against this window")
    self.limit_totals[key] = total
    return result


def _eval_budget(self, inv, B, chain, R):
    total = 0
    for b in B:
        total += effect_cost(b["x"]) * b["count"]
    if inv.get("budget_spent") is not None:
        bs = inv["budget_spent"]
        if isinstance(bs, bool) or not isinstance(bs, (int, float)) \
                or Fraction(bs).limit_denominator(10 ** 9) != total:
            return R("violated", "I7", "host", [],
                     "recorded spend does not match recomputation")
    for node in chain:
        claims = self.claims_of(node)
        if claims["budget"] is not None:
            if self.budget_running.get(node.get("id"), 0) + total > claims["budget"] \
                    and inv.get("approval_ref") is None:
                return R("violated", "I2", "agent", [],
                         "risk budget exceeded")
    for node in chain:
        nid = node.get("id")
        self.budget_running[nid] = self.budget_running.get(nid, 0) + total
    return None


Evaluator.eval_invocation = _eval_invocation
Evaluator._eval_limits = _eval_limits
Evaluator._check_period = _check_period
Evaluator._eval_budget = _eval_budget


# ------------------------------------------------------------------ run / CLI
def run_packet_text(packet_text, keyset, state=None):
    """Evaluate packet JSON text; returns the verdict dict of 10.5 plus
    the 10.8 record fields."""
    try:
        packet, issues = parse_strict(packet_text)
    except StrictParseError:
        results = [_result("-", "unresolved", "I7", None,
                           [{"need": "well_formed_packet", "ref": "-"}],
                           "packet does not parse")]
        return _verdict(results)
    ev = Evaluator(packet, keyset, state, malformed=bool(issues))
    return ev.evaluate()


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="amep_verify")
    ap.add_argument("packet")
    ap.add_argument("--keys", required=True)
    ap.add_argument("--state")
    args = ap.parse_args(argv)
    with open(args.packet, "r", encoding="utf-8") as fh:
        packet_text = fh.read()
    with open(args.keys, "r", encoding="utf-8") as fh:
        keyset = load_js_json(fh.read())
    state = None
    if args.state:
        with open(args.state, "r", encoding="utf-8") as fh:
            state = load_js_json(fh.read())
    verdict = run_packet_text(packet_text, keyset, state)
    print(json.dumps({"outcome": verdict["outcome"],
                      "invariant": verdict["invariant"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
