"""
OSINT Plus — Multi-Tool Open Source Intelligence Platform
Tools: maigret · holehe · ghunt · ipinfo · whois · iginfo · toutatis · hibp · telcek
"""
from flask import Flask, render_template, jsonify, request
import subprocess, json, os, re, hashlib, socket, time, sys, ipaddress, email.parser, logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, quote_plus
from collections import OrderedDict

# Resolve venv-local executables (maigret, etc.)
_SCRIPTS_DIR = os.path.join(os.path.dirname(sys.executable))
MAIGRET_EXE  = os.path.join(_SCRIPTS_DIR, "maigret.exe") if os.name == "nt" else os.path.join(_SCRIPTS_DIR, "maigret")
import phonenumbers
from phonenumbers import geocoder as ph_geocoder, carrier as ph_carrier, timezone as ph_tz
import whois as pywhois
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

_env_path = os.path.join(os.path.dirname(__file__), ".env")
load_dotenv(_env_path, override=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or os.urandom(24)


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' fonts.googleapis.com cdnjs.cloudflare.com; "
        "font-src fonts.gstatic.com cdnjs.cloudflare.com; "
        "img-src * data:; "
        "connect-src 'self'"
    )
    return response

IPINFO_TOKEN        = os.getenv("IPINFO_TOKEN", "")
HIBP_API_KEY        = os.getenv("HIBP_API_KEY", "")
INSTAGRAM_SESSIONID = os.getenv("INSTAGRAM_SESSIONID", "")
GITHUB_TOKEN        = os.getenv("GITHUB_TOKEN", "")
INTELX_KEY          = os.getenv("INTELX_KEY", "")
RAPIDAPI_KEY        = os.getenv("RAPIDAPI_KEY", "")

# ── LRU in-memory cache for Instagram lookups (bounded to 500 entries) ───────
class _LRUCache:
    def __init__(self, maxsize: int = 500, ttl: int = 300):
        self._store: OrderedDict = OrderedDict()
        self.maxsize = maxsize
        self.ttl = ttl

    def get(self, key: str):
        entry = self._store.get(key)
        if entry and (time.time() - entry[0]) < self.ttl:
            self._store.move_to_end(key)
            return entry[1]
        return None

    def set(self, key: str, val: dict):
        if key in self._store:
            self._store.move_to_end(key)
        self._store[key] = (time.time(), val)
        if len(self._store) > self.maxsize:
            self._store.popitem(last=False)


_ig_cache = _LRUCache(maxsize=500, ttl=300)

def _ig_cache_get(key: str):
    return _ig_cache.get(key)

def _ig_cache_set(key: str, data: dict):
    _ig_cache.set(key, data)

# ── Retry helper for Instagram rate-limited endpoints ──────────────────────
def _post_with_retry(url: str, headers: dict, data: str, timeout: int = 10,
                     max_retries: int = 3, base_delay: float = 4.0,
                     cookies: dict | None = None):
    """POST with exponential backoff on 429. Returns (status_code, json_or_None)."""
    for attempt in range(max_retries):
        try:
            resp = requests.post(url, headers=headers, data=data,
                                 cookies=cookies or {}, timeout=timeout)
            if resp.status_code != 429:
                return resp.status_code, resp.json() if resp.content else None
            if attempt < max_retries - 1:
                time.sleep(base_delay * (2 ** attempt))   # 4s → 8s → 16s
        except Exception:
            break
    return 429, None

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}


# ─────────────────────────────────────────────
# ROOT
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


# ─────────────────────────────────────────────
# USERNAME — maigret
# ─────────────────────────────────────────────
@app.route("/api/username/maigret", methods=["POST"])
def username_maigret():
    data = request.json or {}
    username = data.get("username", "").strip()
    if not username or not re.match(r"^[\w.\-]{1,50}$", username):
        return jsonify({"error": "Invalid username (1-50 chars, alphanumeric/._-)"}), 400

    import tempfile, glob as _glob
    tmpdir = tempfile.mkdtemp(prefix="maigret_")
    try:
        result = subprocess.run(
            [MAIGRET_EXE, username,
             "-J", "simple",
             "--no-progressbar",
             "--timeout", "8",
             "--retries", "1",
             "--top-sites", "300",
             "--folderoutput", tmpdir],
            capture_output=True, text=True, timeout=90
        )

        raw_output = (result.stdout or "") + (result.stderr or "")
        found_sites = []

        # Read the JSON report file maigret wrote
        json_files = _glob.glob(os.path.join(tmpdir, "*.json"))
        if json_files:
            try:
                with open(json_files[0], encoding="utf-8") as f:
                    jdata = json.load(f)
                for site, info in jdata.items():
                    status = info.get("status", {})
                    # status is a dict: {"status": "Claimed"|"Found"|"Not Found", ...}
                    if isinstance(status, dict):
                        sid = status.get("status", "")
                    else:
                        sid = str(status)
                    if sid.lower() in ("claimed", "found"):
                        tags = status.get("tags", info.get("tags", []))
                        found_sites.append({
                            "site":     site,
                            "url":      info.get("url_user") or status.get("url", ""),
                            "status":   "FOUND",
                            "category": tags[0] if tags else "other",
                        })
            except Exception:
                pass

        # Fallback: parse text lines "[+] Site - URL"
        if not found_sites:
            for line in raw_output.split("\n"):
                if "[+]" in line:
                    m = re.search(r"https?://\S+", line)
                    site_m = re.match(r"\[.\]\s+(.+?)[\s\-:]+https?://", line)
                    found_sites.append({
                        "site":     site_m.group(1).strip() if site_m else line.replace("[+]", "").strip(),
                        "url":      m.group(0) if m else "",
                        "status":   "FOUND",
                        "category": "social",
                    })

        return jsonify({
            "username": username,
            "found":    found_sites,
            "total":    len(found_sites),
            "raw":      raw_output[:3000],
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Search timed out (180 s)", "username": username}), 408
    except FileNotFoundError:
        return jsonify({"error": f"maigret not found at {MAIGRET_EXE}"}), 500
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


# ─────────────────────────────────────────────
# EMAIL — holehe
# ─────────────────────────────────────────────
@app.route("/api/email/holehe", methods=["POST"])
def email_holehe():
    data = request.json or {}
    email = data.get("email", "").strip()
    if not email or "@" not in email:
        return jsonify({"error": "Invalid email address"}), 400

    try:
        import asyncio, httpx
        from holehe.core import import_submodules, get_functions

        async def _run():
            client = httpx.AsyncClient()
            mods = import_submodules("holehe.modules")
            funcs = get_functions(mods)
            out = []
            for fn in funcs:
                try:
                    await fn(email, client, out)
                except Exception:
                    pass
            await client.aclose()
            return out

        loop = asyncio.new_event_loop()
        results = loop.run_until_complete(_run())
        loop.close()

        found     = [r for r in results if r.get("exists")]
        not_found = [r for r in results if not r.get("exists") and r.get("name")]

        return jsonify({
            "email":         email,
            "found":         found,
            "not_found":     not_found,
            "total_checked": len(results),
            "total_found":   len(found),
        })

    except ImportError:
        return jsonify({"error": "holehe not installed — run: pip install holehe"}), 500
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ─────────────────────────────────────────────
# EMAIL — email OSINT (Disify + Gravatar)
# ─────────────────────────────────────────────
@app.route("/api/email/ghunt", methods=["POST"])
def email_ghunt():
    data = request.json or {}
    email = data.get("email", "").strip().lower()
    if not email or "@" not in email:
        return jsonify({"error": "Invalid email"}), 400

    domain = email.split("@")[1]
    result = {
        "email":    email,
        "domain":   domain,
        "is_gmail": domain in ("gmail.com", "googlemail.com"),
        "sources":  [],
    }

    # Disify — format, disposable, MX, DNS, whitelist, role, free provider
    try:
        dis = requests.get(
            f"https://www.disify.com/api/email/{email}",
            timeout=10
        )
        if dis.status_code == 200:
            d = dis.json()
            result.update({
                "format_valid":    d.get("format", False),
                "disposable":      d.get("disposable", False),
                "has_dns":         d.get("dns", False),
                "whitelisted":     d.get("whitelist", False),
                "is_role_email":   d.get("role", False),
                "is_free_provider":d.get("free", False),
                "mx_records":      d.get("mx_info", []),
            })
            result["sources"].append("disify")
    except Exception:
        pass

    # Gravatar
    md5_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    try:
        gr = requests.get(f"https://www.gravatar.com/avatar/{md5_hash}?d=404", timeout=8)
        result["gravatar"] = {
            "exists": gr.status_code == 200,
            "url":    f"https://www.gravatar.com/avatar/{md5_hash}?s=200",
        }
        result["sources"].append("gravatar")
    except Exception:
        result["gravatar"] = {"exists": False, "url": None}

    # Investigation links
    result["links"] = {
        "google_search":  f'https://www.google.com/search?q="{email}"',
        "linkedin_search":f"https://www.linkedin.com/search/results/people/?keywords={email}",
        "twitter_search": f"https://twitter.com/search?q={email}",
        "gravatar_profile":f"https://en.gravatar.com/{md5_hash}",
        "dehashed":       f"https://www.dehashed.com/search?query={email}",
    }

    return jsonify(result)


# ─────────────────────────────────────────────
# PHONE — ipinfo (phonenumbers + ipinfo.io)
# ─────────────────────────────────────────────
@app.route("/api/phone", methods=["POST"])
def phone_lookup():
    data = request.json or {}
    number = data.get("number", "").strip()
    if not number:
        return jsonify({"error": "Phone number required"}), 400

    result = {"raw": number, "sources": []}

    # phonenumbers library
    try:
        parsed = phonenumbers.parse(number, None)
        num_type = phonenumbers.number_type(parsed)
        type_map = {
            phonenumbers.PhoneNumberType.MOBILE:       "MOBILE",
            phonenumbers.PhoneNumberType.FIXED_LINE:   "FIXED_LINE",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED/MOBILE",
            phonenumbers.PhoneNumberType.TOLL_FREE:    "TOLL_FREE",
            phonenumbers.PhoneNumberType.VOIP:         "VOIP",
            phonenumbers.PhoneNumberType.PAGER:        "PAGER",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "PREMIUM_RATE",
        }
        result.update({
            "valid":         phonenumbers.is_valid_number(parsed),
            "possible":      phonenumbers.is_possible_number(parsed),
            "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national":      phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "e164":          phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "country_code":  parsed.country_code,
            "country":       ph_geocoder.description_for_number(parsed, "en"),
            "region":        phonenumbers.region_code_for_number(parsed),
            "carrier":       ph_carrier.name_for_number(parsed, "en"),
            "timezones":     list(ph_tz.time_zones_for_number(parsed)),
            "line_type":     type_map.get(num_type, "UNKNOWN"),
        })
        result["sources"].append("phonenumbers")
    except Exception as exc:
        result["parse_error"] = str(exc)

    # ipinfo.io (token via Authorization header, not URL param)
    e164 = result.get("e164", re.sub(r"[^\d+]", "", number))
    try:
        _ipinfo_hdrs = {"Authorization": f"Bearer {IPINFO_TOKEN}"} if IPINFO_TOKEN else {}
        r = requests.get(f"https://ipinfo.io/{e164}/json", headers=_ipinfo_hdrs, timeout=10)
        if r.status_code == 200:
            result["ipinfo"] = r.json()
            result["sources"].append("ipinfo.io")
    except Exception:
        pass

    return jsonify(result)


# ─────────────────────────────────────────────
# DOMAIN — whois
# ─────────────────────────────────────────────
@app.route("/api/domain", methods=["POST"])
def domain_lookup():
    data = request.json or {}
    domain = data.get("domain", "").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0].split("?")[0]
    if not domain or "." not in domain:
        return jsonify({"error": "Invalid domain"}), 400

    result = {"domain": domain, "sources": []}

    # WHOIS
    try:
        w = pywhois.whois(domain)

        def _str(v):
            if v is None:
                return None
            if isinstance(v, list):
                v = v[0]
            return str(v)

        result.update({
            "registrar":       w.registrar,
            "creation_date":   _str(w.creation_date),
            "expiration_date": _str(w.expiration_date),
            "updated_date":    _str(w.updated_date),
            "name_servers":    [str(ns).upper() for ns in (w.name_servers or [])],
            "status":          [str(s).split()[0] for s in (w.status or [])],
            "registrant_org":  w.org or w.registrant_name,
            "country":         w.country,
            "city":            w.city,
            "emails":          list(set(w.emails)) if w.emails else [],
            "dnssec":          str(w.dnssec) if w.dnssec else None,
        })
        result["sources"].append("whois")
    except Exception as exc:
        result["whois_error"] = str(exc)

    # DNS + IP
    try:
        ip = socket.gethostbyname(domain)
        # Block SSRF: refuse to follow domains that resolve to private ranges
        try:
            _resolved = ipaddress.ip_address(ip)
            if _resolved.is_private or _resolved.is_loopback or _resolved.is_link_local:
                result["resolves"] = True
                result["ip_address"] = ip
                result["ssrf_blocked"] = True
                ip = None  # skip ipinfo call
        except ValueError:
            pass

        if ip:
            result["ip_address"] = ip
            result["resolves"]   = True
            result["sources"].append("dns")

        _ipinfo_headers = {"Authorization": f"Bearer {IPINFO_TOKEN}"} if IPINFO_TOKEN else {}
        r = requests.get(f"https://ipinfo.io/{ip}/json", headers=_ipinfo_headers, timeout=8) if ip else None
        if r and r.status_code == 200:
            ipd = r.json()
            result["ip_info"] = {
                "ip":       ipd.get("ip"),
                "city":     ipd.get("city"),
                "region":   ipd.get("region"),
                "country":  ipd.get("country"),
                "org":      ipd.get("org"),
                "timezone": ipd.get("timezone"),
                "loc":      ipd.get("loc"),
            }
            result["sources"].append("ipinfo.io")
    except Exception as exc:
        result["resolves"]  = False
        result["dns_error"] = str(exc)

    # SSL certificate check
    try:
        import ssl
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(8)
            s.connect((domain, 443))
            cert = s.getpeercert()
            result["ssl"] = {
                "issuer":   dict(x[0] for x in cert.get("issuer", [])),
                "subject":  dict(x[0] for x in cert.get("subject", [])),
                "not_after": cert.get("notAfter"),
                "sans":     [v for _, v in cert.get("subjectAltName", [])],
            }
    except Exception:
        result["ssl"] = None

    return jsonify(result)


# ─────────────────────────────────────────────
# IP — Geolocation (ip-api.com)
# ─────────────────────────────────────────────
@app.route("/api/ip", methods=["POST"])
def ip_lookup():
    data = request.json or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP address required"}), 400

    # Basic IPv4/IPv6 sanity check
    ip_clean = re.sub(r"[^0-9a-fA-F:.]", "", ip)
    if not ip_clean:
        return jsonify({"error": "Invalid IP address"}), 400

    # Block private / loopback / link-local addresses (SSRF prevention)
    try:
        _addr = ipaddress.ip_address(ip_clean)
        if _addr.is_private or _addr.is_loopback or _addr.is_link_local or _addr.is_reserved:
            return jsonify({"error": "Private or reserved IP addresses are not allowed"}), 400
    except ValueError:
        return jsonify({"error": "Invalid IP address format"}), 400

    try:
        fields = "status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
        r = requests.get(
            f"http://ip-api.com/json/{ip_clean}?fields={fields}",
            timeout=10
        )
        if r.status_code != 200:
            return jsonify({"error": f"ip-api.com error: HTTP {r.status_code}"}), 502

        d = r.json()
        if d.get("status") == "fail":
            return jsonify({"error": d.get("message", "Invalid or reserved IP")}), 400

        result = {
            "ip":           d.get("query"),
            "continent":    d.get("continent"),
            "country":      d.get("country"),
            "country_code": d.get("countryCode"),
            "region":       d.get("regionName"),
            "city":         d.get("city"),
            "district":     d.get("district") or None,
            "zip":          d.get("zip") or None,
            "lat":          d.get("lat"),
            "lon":          d.get("lon"),
            "timezone":     d.get("timezone"),
            "currency":     d.get("currency"),
            "isp":          d.get("isp"),
            "org":          d.get("org"),
            "asn":          d.get("as"),
            "asname":       d.get("asname"),
            "reverse_dns":  d.get("reverse") or None,
            "is_mobile":    d.get("mobile", False),
            "is_proxy":     d.get("proxy", False),
            "is_hosting":   d.get("hosting", False),
            "map_url":      f"https://www.google.com/maps?q={d.get('lat')},{d.get('lon')}",
            "source":       "ip-api.com",
        }
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ─────────────────────────────────────────────
# GITHUB — Profile OSINT
# ─────────────────────────────────────────────
@app.route("/api/github", methods=["POST"])
def github_osint():
    data = request.json or {}
    username = data.get("username", "").strip().lstrip("@")
    if not username or not re.match(r"^[\w\-]{1,39}$", username):
        return jsonify({"error": "Invalid GitHub username"}), 400

    gh_headers = {"Accept": "application/vnd.github+json",
                  "User-Agent": "OsintPlus"}
    if GITHUB_TOKEN:
        gh_headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    try:
        # Basic profile
        r = requests.get(f"https://api.github.com/users/{username}",
                         headers=gh_headers, timeout=10)
        if r.status_code == 404:
            return jsonify({"error": f"GitHub user '{username}' not found"}), 404
        if r.status_code == 403:
            return jsonify({"error": "GitHub API rate limit reached. Set GITHUB_TOKEN in .env"}), 429
        if r.status_code != 200:
            return jsonify({"error": f"GitHub API error: HTTP {r.status_code}"}), 502

        u = r.json()
        result = {
            "username":     u.get("login"),
            "name":         u.get("name"),
            "bio":          u.get("bio"),
            "company":      u.get("company"),
            "location":     u.get("location"),
            "email":        u.get("email"),
            "website":      u.get("blog"),
            "twitter":      u.get("twitter_username"),
            "avatar_url":   u.get("avatar_url"),
            "github_url":   u.get("html_url"),
            "type":         u.get("type"),           # User / Organization
            "public_repos": u.get("public_repos"),
            "public_gists": u.get("public_gists"),
            "followers":    u.get("followers"),
            "following":    u.get("following"),
            "created_at":   u.get("created_at"),
            "updated_at":   u.get("updated_at"),
            "hireable":     u.get("hireable"),
            "repos":        [],
            "commit_emails":[],
        }

        # Top repos (sorted by stars)
        try:
            rr = requests.get(
                f"https://api.github.com/users/{username}/repos?per_page=100&sort=pushed",
                headers=gh_headers, timeout=10)
            if rr.status_code == 200:
                repos = rr.json()
                repos_sorted = sorted(repos, key=lambda x: x.get("stargazers_count", 0), reverse=True)
                result["repos"] = [
                    {
                        "name":        repo["name"],
                        "description": repo.get("description"),
                        "language":    repo.get("language"),
                        "stars":       repo.get("stargazers_count", 0),
                        "forks":       repo.get("forks_count", 0),
                        "url":         repo.get("html_url"),
                        "fork":        repo.get("fork", False),
                    }
                    for repo in repos_sorted[:10]
                ]
        except Exception:
            pass

        # Extract emails from public commit events
        emails_found = set()
        try:
            ev = requests.get(
                f"https://api.github.com/users/{username}/events/public?per_page=50",
                headers=gh_headers, timeout=10)
            if ev.status_code == 200:
                for event in ev.json():
                    if event.get("type") == "PushEvent":
                        for commit in event.get("payload", {}).get("commits", []):
                            author = commit.get("author", {})
                            email = author.get("email", "")
                            name  = author.get("name", "")
                            if email and not email.endswith("@users.noreply.github.com"):
                                emails_found.add(f"{name} <{email}>")
        except Exception:
            pass

        result["commit_emails"] = list(emails_found)
        return jsonify(result)

    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ─────────────────────────────────────────────
# USERNAME — Multi-platform checker
# ─────────────────────────────────────────────
_PLATFORMS = [
    {"name":"GitHub",    "cat":"dev",      "url":"https://github.com/{}",                        "found":[200], "not_found":[404]},
    {"name":"Reddit",    "cat":"social",   "url":"https://www.reddit.com/user/{}/",               "found":[200], "not_found":[404]},
    {"name":"Twitter/X", "cat":"social",   "url":"https://twitter.com/{}",                        "found":[200], "not_found":[404]},
    {"name":"YouTube",   "cat":"social",   "url":"https://www.youtube.com/@{}",                   "found":[200], "not_found":[404]},
    {"name":"Twitch",    "cat":"gaming",   "url":"https://www.twitch.tv/{}",                      "found":[200], "not_found":[404]},
    {"name":"Pinterest", "cat":"social",   "url":"https://www.pinterest.com/{}/",                 "found":[200], "not_found":[404]},
    {"name":"Snapchat",  "cat":"social",   "url":"https://www.snapchat.com/add/{}",               "found":[200], "not_found":[404]},
    {"name":"Medium",    "cat":"blog",     "url":"https://medium.com/@{}",                        "found":[200], "not_found":[404]},
    {"name":"Telegram",  "cat":"messenger","url":"https://t.me/{}",                               "found":[200], "not_found":[404],
     "absent_text":"tgme_page_description"},
    {"name":"Steam",     "cat":"gaming",   "url":"https://steamcommunity.com/id/{}",              "found":[200], "not_found":[404],
     "absent_text":"error_ctn"},
    {"name":"Keybase",   "cat":"security", "url":"https://keybase.io/{}",                         "found":[200], "not_found":[404]},
    {"name":"Dev.to",    "cat":"dev",      "url":"https://dev.to/{}",                             "found":[200], "not_found":[404]},
    {"name":"Linktree",  "cat":"social",   "url":"https://linktr.ee/{}",                          "found":[200], "not_found":[404]},
    {"name":"HackerNews","cat":"dev",      "url":"https://news.ycombinator.com/user?id={}",       "found":[200], "not_found":[404],
     "absent_text":"No such user"},
    {"name":"GitLab",    "cat":"dev",      "url":"https://gitlab.com/{}",                         "found":[200], "not_found":[404]},
]

def _check_one_platform(plat: dict, username: str) -> dict:
    url = plat["url"].format(username)
    ua  = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
           "AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/124.0.0.0 Safari/537.36")
    try:
        resp = requests.get(url, headers={"User-Agent": ua},
                            timeout=7, allow_redirects=True)
        code = resp.status_code

        # Content-based false-positive filter
        if code in plat.get("found", [200]) and "absent_text" in plat:
            if plat["absent_text"] in resp.text:
                return {"name": plat["name"], "cat": plat["cat"],
                        "status": "not_found", "url": url}

        if code in plat.get("found", [200]):
            return {"name": plat["name"], "cat": plat["cat"],
                    "status": "found", "url": url}
        if code in plat.get("not_found", [404]):
            return {"name": plat["name"], "cat": plat["cat"],
                    "status": "not_found", "url": url}
        return {"name": plat["name"], "cat": plat["cat"],
                "status": "unknown", "url": url, "http": code}
    except requests.Timeout:
        return {"name": plat["name"], "cat": plat["cat"],
                "status": "timeout", "url": url}
    except Exception:
        return {"name": plat["name"], "cat": plat["cat"],
                "status": "error", "url": url}

@app.route("/api/username/multicheck", methods=["POST"])
def username_multicheck():
    data = request.json or {}
    username = data.get("username", "").strip().lstrip("@")
    if not username or not re.match(r"^[\w.\-]{1,50}$", username):
        return jsonify({"error": "Invalid username"}), 400

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_check_one_platform, p, username): p
                   for p in _PLATFORMS}
        results = [f.result() for f in as_completed(futures)]

    found     = [r for r in results if r["status"] == "found"]
    not_found = [r for r in results if r["status"] == "not_found"]
    unknown   = [r for r in results if r["status"] not in ("found", "not_found")]

    return jsonify({
        "username":   username,
        "found":      sorted(found,     key=lambda x: x["name"]),
        "not_found":  sorted(not_found, key=lambda x: x["name"]),
        "unknown":    sorted(unknown,   key=lambda x: x["name"]),
        "total":      len(_PLATFORMS),
        "found_count":len(found),
    })


# ─────────────────────────────────────────────
# INSTAGRAM — iginfo (instaloader)
# ─────────────────────────────────────────────
@app.route("/api/instagram/info", methods=["POST"])
def instagram_info():
    from urllib.parse import unquote
    import instaloader
    data = request.json or {}
    username = data.get("username", "").strip().lstrip("@")
    if not username:
        return jsonify({"error": "Username required"}), 400

    session_id = unquote(INSTAGRAM_SESSIONID) if INSTAGRAM_SESSIONID else ""
    if not session_id:
        return jsonify({"error": "INSTAGRAM_SESSIONID belum diset di .env"}), 400

    # Extract user_id from session_id (format: userid:hash:num:token)
    parts = session_id.split(":")
    user_id_str = parts[0] if parts else ""

    try:
        L = instaloader.Instaloader(quiet=True, download_pictures=False,
                                    download_videos=False, download_video_thumbnails=False,
                                    compress_json=False, save_metadata=False)
        L.context._session.cookies.set("sessionid", session_id, domain=".instagram.com")
        if user_id_str:
            L.context._session.cookies.set("ds_user_id", user_id_str, domain=".instagram.com")

        profile = instaloader.Profile.from_username(L.context, username)
        return jsonify({
            "username":          profile.username,
            "userid":            profile.userid,
            "full_name":         profile.full_name,
            "biography":         profile.biography,
            "followers":         profile.followers,
            "followees":         profile.followees,
            "posts":             profile.mediacount,
            "is_private":        profile.is_private,
            "is_verified":       profile.is_verified,
            "is_business":       profile.is_business_account,
            "business_category": profile.business_category_name,
            "external_url":      profile.external_url,
            "profile_pic_url":   profile.profile_pic_url,
            "instagram_url":     f"https://www.instagram.com/{username}/",
        })
    except instaloader.exceptions.ProfileNotExistsException:
        return jsonify({"error": f"Profile '{username}' tidak ditemukan"}), 404
    except instaloader.exceptions.LoginRequiredException:
        return jsonify({"error": "Session ID tidak valid atau sudah expired. Perbarui INSTAGRAM_SESSIONID di .env"}), 401
    except instaloader.exceptions.ConnectionException as exc:
        return jsonify({"error": f"Koneksi ke Instagram gagal: {exc}"}), 503
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ─────────────────────────────────────────────
# INSTAGRAM — toutatis (deep OSINT, needs sessionid)
# ─────────────────────────────────────────────
@app.route("/api/instagram/toutatis", methods=["POST"])
def instagram_toutatis():
    from urllib.parse import unquote
    from urllib.parse import quote_plus
    from json import dumps as jdumps, decoder as jdecoder
    import instaloader

    data = request.json or {}
    username  = data.get("username", "").strip().lstrip("@").lower()
    sessionid = unquote(INSTAGRAM_SESSIONID.strip()) if INSTAGRAM_SESSIONID else ""

    if not username:
        return jsonify({"error": "Username required"}), 400
    if not sessionid:
        return jsonify({"error": "Instagram sessionid required (set INSTAGRAM_SESSIONID di .env)"}), 400

    # ── Cache check ────────────────────────────────────────────────────────
    cache_key = f"toutatis:{username}"
    cached = _ig_cache_get(cache_key)
    if cached:
        return jsonify({**cached, "_cached": True})

    try:
        # Step 1: resolve user_id via instaloader (bypasses blocked web_profile_info)
        L = instaloader.Instaloader(quiet=True, download_pictures=False,
                                    download_videos=False, download_video_thumbnails=False,
                                    compress_json=False, save_metadata=False)
        parts = sessionid.split(":")
        L.context._session.cookies.set("sessionid", sessionid, domain=".instagram.com")
        if parts:
            L.context._session.cookies.set("ds_user_id", parts[0], domain=".instagram.com")

        try:
            profile = instaloader.Profile.from_username(L.context, username)
        except instaloader.exceptions.ProfileNotExistsException:
            return jsonify({"error": f"Profile '{username}' tidak ditemukan"}), 404
        except instaloader.exceptions.LoginRequiredException:
            return jsonify({"error": "Session ID tidak valid atau sudah expired"}), 401

        user_id = str(profile.userid)

        # Step 2: call Instagram mobile API for deep info
        mobile_resp = requests.get(
            f"https://i.instagram.com/api/v1/users/{user_id}/info/",
            headers={"User-Agent": "Instagram 64.0.0.14.96"},
            cookies={"sessionid": sessionid},
            timeout=15,
        )
        if mobile_resp.status_code != 200:
            return jsonify({"error": f"Instagram mobile API error: HTTP {mobile_resp.status_code}"}), mobile_resp.status_code

        u = mobile_resp.json().get("user", {})

        # Step 3: advanced_lookup — retry with exponential backoff on 429
        lookup_result = {}
        try:
            lookup_body = "signed_body=SIGNATURE." + quote_plus(
                jdumps({"q": username, "skip_recovery": "1"}, separators=(",", ":"))
            )
            lookup_headers = {
                "Accept-Language": "en-US",
                "User-Agent": "Instagram 314.0.0.35.109 Android (30/11; 420dpi; 1080x2148; samsung; SM-G975U; beyond2q; qcom; en_US; 548756459)",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "X-IG-App-ID": "124024574287414",
                "Accept-Encoding": "gzip, deflate",
                "Host": "i.instagram.com",
                "Connection": "keep-alive",
            }
            status, ld = _post_with_retry(
                "https://i.instagram.com/api/v1/users/lookup/",
                headers=lookup_headers,
                data=lookup_body,
                timeout=10,
                max_retries=3,
                base_delay=4.0,
                cookies={"sessionid": sessionid},
            )
            if status == 200 and ld:
                lookup_result = {
                    "obfuscated_email": ld.get("obfuscated_email"),
                    "obfuscated_phone": ld.get("obfuscated_phone"),
                }
            elif status == 429:
                lookup_result = {"lookup_status": "rate limited — IP terlalu banyak request, coba beberapa menit lagi"}
            elif status == 400:
                lookup_result = {"lookup_status": "bad request — endpoint Instagram berubah"}
            else:
                lookup_result = {"lookup_status": f"gagal (HTTP {status})"}
        except Exception as e:
            lookup_result = {"lookup_status": f"error: {e}"}

        # Build phone string if available
        phone_str = None
        if u.get("public_phone_number"):
            phone_str = f"+{u.get('public_phone_country_code', '')} {u.get('public_phone_number', '')}".strip()

        result = {
            "username":             u.get("username"),
            "user_id":              user_id,
            "full_name":            u.get("full_name"),
            "biography":            u.get("biography"),
            "account_type":         u.get("account_type"),
            "is_private":           u.get("is_private"),
            "is_verified":          u.get("is_verified"),
            "is_business":          u.get("is_business"),
            "is_whatsapp_linked":   u.get("is_whatsapp_linked"),
            "is_memorialized":      u.get("is_memorialized"),
            "is_new_to_instagram":  u.get("is_new_to_instagram"),
            "follower_count":       u.get("follower_count"),
            "following_count":      u.get("following_count"),
            "media_count":          u.get("media_count"),
            "total_igtv_videos":    u.get("total_igtv_videos"),
            "external_url":         u.get("external_url"),
            "public_email":         u.get("public_email") or None,
            "public_phone":         phone_str,
            "profile_pic_url":      (u.get("hd_profile_pic_url_info") or {}).get("url") or u.get("profile_pic_url"),
            "instagram_url":        f"https://www.instagram.com/{username}/",
            "lookup":               lookup_result,
        }

        # Simpan ke cache hanya jika lookup berhasil mendapat data
        if not lookup_result.get("lookup_status"):
            _ig_cache_set(cache_key, result)

        return jsonify(result)

    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ─────────────────────────────────────────────
# SECURITY — HIBP Email breach check
# ─────────────────────────────────────────────
@app.route("/api/hibp/email", methods=["POST"])
def hibp_email():
    data = request.json or {}
    email = data.get("email", "").strip()
    if not email or "@" not in email:
        return jsonify({"error": "Invalid email"}), 400

    if not HIBP_API_KEY:
        return jsonify({
            "error": "HIBP API key required. Get one at haveibeenpwned.com/API/Key",
            "email": email,
        }), 403

    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "OsintPlus-Security-Tool",
    }
    result = {"email": email, "breaches": [], "pastes": [], "breached": False}

    # Breach check with exponential backoff (max 3 retries)
    for attempt in range(3):
        try:
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
                headers=headers, timeout=15
            )
            if r.status_code == 200:
                result["breaches"] = r.json()
                result["breached"] = True
                result["total_breaches"] = len(result["breaches"])
                break
            elif r.status_code == 404:
                result["breached"] = False
                result["total_breaches"] = 0
                break
            elif r.status_code == 429:
                if attempt < 2:
                    time.sleep(1.5 * (2 ** attempt))   # 1.5s → 3s → give up
                else:
                    result["breach_error"] = "Rate limited by HIBP — coba beberapa detik lagi"
            else:
                result["breach_error"] = f"HTTP {r.status_code}"
                break
        except Exception as exc:
            result["breach_error"] = str(exc)
            break

    # Paste check (best-effort, single attempt)
    try:
        r2 = requests.get(
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
            headers=headers, timeout=15
        )
        if r2.status_code == 200:
            result["pastes"] = r2.json()
            result["total_pastes"] = len(result["pastes"])
    except Exception:
        pass

    return jsonify(result)


# ─────────────────────────────────────────────
# SECURITY — HIBP Password check (k-anonymity, no key needed)
# ─────────────────────────────────────────────
@app.route("/api/hibp/password", methods=["POST"])
def hibp_password():
    data = request.json or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "Password required"}), 400

    sha1   = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
        hashes = {}
        for line in r.text.strip().split("\n"):
            parts = line.strip().split(":")
            if len(parts) == 2:
                hashes[parts[0]] = int(parts[1])

        count = hashes.get(suffix, 0)
        return jsonify({
            "pwned": count > 0,
            "count": count,
            "severity": "critical" if count > 100000 else "high" if count > 1000 else "medium" if count > 0 else "safe",
            "message": (
                f"Password found {count:,} times in data breaches — CHANGE IT IMMEDIATELY!"
                if count > 0
                else "Password not found in any known breach database."
            ),
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ─────────────────────────────────────────────
# MESSENGER — telcek (Telegram / WhatsApp / Signal check)
# ─────────────────────────────────────────────
@app.route("/api/messenger", methods=["POST"])
def messenger_check():
    data = request.json or {}
    number = data.get("number", "").strip()
    if not number:
        return jsonify({"error": "Phone number required"}), 400

    result = {"number": number, "platforms": {}, "phone_info": {}}

    # Parse phone number
    try:
        parsed   = phonenumbers.parse(number, None)
        is_valid = phonenumbers.is_valid_number(parsed)
        e164     = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        clean    = re.sub(r"[^\d]", "", e164)
        result["phone_info"] = {
            "valid":         is_valid,
            "country":       ph_geocoder.description_for_number(parsed, "en"),
            "carrier":       ph_carrier.name_for_number(parsed, "en"),
            "region":        phonenumbers.region_code_for_number(parsed),
            "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        }
    except Exception as exc:
        result["parse_error"] = str(exc)
        clean = re.sub(r"[^\d]", "", number)

    # WhatsApp
    try:
        wa_url = f"https://wa.me/{clean}"
        r_wa = requests.get(wa_url, headers=BROWSER_HEADERS, timeout=10, allow_redirects=True)
        wa_exists = "whatsapp" in r_wa.url.lower() or r_wa.status_code == 200
        result["platforms"]["whatsapp"] = {
            "check_url":    wa_url,
            "status":       "possible" if wa_exists else "unknown",
            "note":         "Open link to verify manually",
        }
    except Exception as exc:
        result["platforms"]["whatsapp"] = {"status": "error", "error": str(exc)}

    # Telegram deep link
    result["platforms"]["telegram"] = {
        "deep_link":    f"https://t.me/+{clean}",
        "status":       "manual_check",
        "note":         "Click deep link to verify Telegram registration",
        "search_link":  f"https://t.me/+{clean}",
    }

    # Viber deep link
    result["platforms"]["viber"] = {
        "deep_link": f"viber://chat?number=%2B{clean}",
        "status":    "manual_check",
        "note":      "Requires Viber installed",
    }

    # Signal
    result["platforms"]["signal"] = {
        "status": "no_public_api",
        "note":   "Signal has no public lookup API by design",
    }

    # Truecaller web search
    try:
        tc_url = f"https://www.truecaller.com/search/us/{clean}"
        result["platforms"]["truecaller"] = {
            "search_url": tc_url,
            "status":     "manual_check",
        }
    except Exception:
        pass

    return jsonify(result)


# ─────────────────────────────────────────────
# EMAIL — Header Analyzer
# ─────────────────────────────────────────────
def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except Exception:
        return False

def _extract_auth_status(auth_str: str, proto: str) -> str:
    m = re.search(rf'{proto}=(\w+)', auth_str, re.IGNORECASE)
    return m.group(1) if m else "none"

@app.route("/api/email/header", methods=["POST"])
def email_header_analyzer():
    data = request.json or {}
    raw = data.get("headers", "").strip()
    if not raw:
        return jsonify({"error": "Email headers required"}), 400
    if len(raw) > 65_536:
        return jsonify({"error": "Headers too large (max 64 KB)"}), 413

    parser = email.parser.HeaderParser()
    msg = parser.parsestr(raw)

    result = {
        "from":              msg.get("From"),
        "to":                msg.get("To"),
        "subject":           msg.get("Subject"),
        "date":              msg.get("Date"),
        "message_id":        msg.get("Message-ID"),
        "reply_to":          msg.get("Reply-To"),
        "return_path":       msg.get("Return-Path"),
        "x_mailer":          msg.get("X-Mailer"),
        "user_agent":        msg.get("User-Agent"),
        "x_originating_ip":  msg.get("X-Originating-IP"),
        "content_type":      msg.get("Content-Type"),
    }

    # Hop chain from Received headers
    received_list = msg.get_all("Received") or []
    hop_chain = []
    for r in reversed(received_list):   # oldest hop first
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', r)
        public_ips = list(set(ip for ip in ips if not _is_private_ip(ip)))
        by_m = re.search(r'\bby\s+([\w.\-]+)', r, re.IGNORECASE)
        from_m = re.search(r'\bfrom\s+([\w.\-]+)', r, re.IGNORECASE)
        delay_m = re.search(r';\s*(.+)$', r.strip())
        hop_chain.append({
            "from_host": from_m.group(1) if from_m else None,
            "by_host":   by_m.group(1)   if by_m   else None,
            "public_ips": public_ips,
            "timestamp": delay_m.group(1).strip() if delay_m else None,
        })
    result["hop_chain"] = hop_chain
    result["hop_count"] = len(hop_chain)

    # Authentication
    auth_results = msg.get("Authentication-Results", "") or ""
    arc_auth     = msg.get("ARC-Authentication-Results", "") or ""
    dkim_sig     = msg.get("DKIM-Signature", "") or ""
    combined_auth = auth_results + " " + arc_auth

    result["authentication"] = {
        "dkim": {
            "present": bool(dkim_sig),
            "pass":    "dkim=pass" in combined_auth.lower(),
            "fail":    "dkim=fail" in combined_auth.lower(),
            "status":  _extract_auth_status(combined_auth, "dkim"),
        },
        "spf": {
            "pass":   "spf=pass" in combined_auth.lower(),
            "fail":   any(x in combined_auth.lower() for x in ("spf=fail", "spf=softfail")),
            "status": _extract_auth_status(combined_auth, "spf"),
        },
        "dmarc": {
            "pass":   "dmarc=pass" in combined_auth.lower(),
            "fail":   "dmarc=fail" in combined_auth.lower(),
            "status": _extract_auth_status(combined_auth, "dmarc"),
        },
        "raw": auth_results,
    }

    # Spoofing indicators
    from_addr   = result.get("from") or ""
    return_path = result.get("return_path") or ""
    reply_to    = result.get("reply_to") or ""

    from_domain = re.search(r'@([\w.\-]+)', from_addr)
    rp_domain   = re.search(r'@([\w.\-]+)', return_path)
    indicators  = []

    if from_domain and rp_domain and from_domain.group(1).lower() != rp_domain.group(1).lower():
        indicators.append(f"From domain differs from Return-Path ({from_domain.group(1)} vs {rp_domain.group(1)})")
    if reply_to and from_addr and reply_to.strip().lower() != from_addr.strip().lower():
        indicators.append(f"Reply-To differs from From address")
    if result["authentication"]["dkim"]["fail"]:
        indicators.append("DKIM signature failed verification")
    if result["authentication"]["spf"]["fail"]:
        indicators.append("SPF check failed or softfail")
    if result["authentication"]["dmarc"]["fail"]:
        indicators.append("DMARC policy failed")

    result["spoofing_risk"]       = "high" if len(indicators) >= 2 else "medium" if indicators else "low"
    result["spoofing_indicators"] = indicators

    # Spam headers
    spam_status = msg.get("X-Spam-Status", "") or ""
    spam_score  = msg.get("X-Spam-Score", "")  or msg.get("X-Spam-Level", "")
    result["spam"] = {
        "status":  spam_status,
        "score":   spam_score,
        "flagged": "yes" in spam_status.lower() if spam_status else None,
    }

    return jsonify(result)


# ─────────────────────────────────────────────
# DNS — Deep record lookup
# ─────────────────────────────────────────────
@app.route("/api/dns", methods=["POST"])
def dns_lookup():
    try:
        import dns.resolver, dns.exception
    except ImportError:
        return jsonify({"error": "dnspython not installed — run: pip install dnspython"}), 500

    data = request.json or {}
    domain = data.get("domain", "").strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0].split("?")[0]
    if not domain or "." not in domain:
        return jsonify({"error": "Invalid domain"}), 400

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    result = {"domain": domain, "records": {}}

    def _query(dom, rtype):
        try:
            answers = resolver.resolve(dom, rtype)
            if rtype == "MX":
                return sorted([{"priority": r.preference, "exchange": str(r.exchange).rstrip(".")} for r in answers],
                               key=lambda x: x["priority"])
            if rtype == "SOA":
                r = answers[0]
                return [{"mname": str(r.mname).rstrip("."), "rname": str(r.rname).rstrip("."),
                          "serial": r.serial, "refresh": r.refresh, "retry": r.retry,
                          "expire": r.expire, "minimum": r.minimum}]
            return [str(r).strip('"').rstrip(".") for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return []
        except Exception as e:
            return {"error": str(e)}

    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]:
        result["records"][rtype] = _query(domain, rtype)

    # SPF (from TXT)
    txt = result["records"].get("TXT", [])
    result["spf"] = [r for r in txt if isinstance(r, str) and "v=spf1" in r.lower()]

    # DMARC
    result["dmarc"] = _query(f"_dmarc.{domain}", "TXT")

    # DKIM common selectors
    dkim_found = []
    for sel in ["default", "google", "mail", "dkim", "k1", "s1", "s2", "selector1", "selector2"]:
        records = _query(f"{sel}._domainkey.{domain}", "TXT")
        if records and not isinstance(records, dict):
            dkim_found.append({"selector": sel, "record": records[0] if records else ""})
    result["dkim_selectors"] = dkim_found

    # Basic geo of first A record
    a_records = result["records"].get("A", [])
    if a_records and isinstance(a_records, list):
        try:
            geo = requests.get(f"http://ip-api.com/json/{a_records[0]}?fields=country,regionName,city,isp,org,as",
                               timeout=6)
            if geo.status_code == 200:
                result["ip_geo"] = geo.json()
        except Exception:
            pass

    return jsonify(result)


# ─────────────────────────────────────────────
# LEAK — Paste / breach search (multi-source)
# ─────────────────────────────────────────────
@app.route("/api/leaksearch", methods=["POST"])
def leak_search():
    data = request.json or {}
    query = data.get("query", "").strip()
    if not query or len(query) < 3:
        return jsonify({"error": "Query must be at least 3 characters"}), 400

    is_email = "@" in query
    result   = {"query": query, "results": [], "sources": [], "total": 0, "is_email": is_email}

    # Source 1: psbdmp.ws (free Pastebin dump index — works if network allows)
    try:
        r = requests.get(
            f"https://psbdmp.ws/api/v3/search/{quote(query, safe='')}",
            headers=BROWSER_HEADERS, timeout=8
        )
        if r.status_code == 200:
            payload = r.json()
            pastes = payload if isinstance(payload, list) else payload.get("data", [])
            for p in pastes[:15]:
                result["results"].append({
                    "source":  "psbdmp",
                    "url":     f"https://pastebin.com/{p.get('id')}",
                    "raw_url": f"https://psbdmp.ws/{p.get('id')}",
                    "title":   p.get("id"),
                    "date":    p.get("date") or p.get("time"),
                    "repo":    None,
                })
            result["sources"].append("psbdmp.ws")
    except Exception:
        pass

    # Source 2: HIBP Paste API (email only, requires HIBP_API_KEY)
    if is_email and HIBP_API_KEY:
        try:
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/pasteaccount/{query}",
                headers={"hibp-api-key": HIBP_API_KEY, "User-Agent": "OsintPlus-Security-Tool"},
                timeout=12
            )
            if r.status_code == 200:
                for p in r.json():
                    result["results"].append({
                        "source":  "hibp-paste",
                        "url":     p.get("Source", ""),
                        "raw_url": None,
                        "title":   f"{p.get('Source','')} · {p.get('Id','')}",
                        "date":    p.get("Date"),
                        "repo":    None,
                    })
                result["sources"].append("HIBP")
        except Exception:
            pass

    # Source 3: IntelX API (optional — set INTELX_KEY in .env, free at intelx.io)
    if INTELX_KEY:
        try:
            ix_start = requests.post(
                "https://2.intelx.io/intelligent/search",
                json={
                    "term": query, "buckets": [], "lookuplevel": 0,
                    "maxresults": 10, "timeout": 0, "datefrom": "", "dateto": "",
                    "sort": 4, "media": 0, "terminate": [],
                },
                headers={"x-key": INTELX_KEY, "Content-Type": "application/json"},
                timeout=10,
            )
            if ix_start.status_code == 200:
                ix_id = ix_start.json().get("id")
                time.sleep(1)
                ix_res = requests.get(
                    f"https://2.intelx.io/intelligent/search/result?id={ix_id}&limit=10&offset=0",
                    headers={"x-key": INTELX_KEY},
                    timeout=10,
                )
                if ix_res.status_code == 200:
                    for item in ix_res.json().get("records", [])[:10]:
                        result["results"].append({
                            "source":  "intelx",
                            "url":     f"https://intelx.io/?did={item.get('systemid','')}",
                            "raw_url": None,
                            "title":   item.get("name") or item.get("bucket", ""),
                            "date":    item.get("date"),
                            "repo":    item.get("bucket"),
                        })
                    if ix_res.json().get("records"):
                        result["sources"].append("intelx.io")
        except Exception:
            pass

    # Source 4: BreachDirectory via RapidAPI (requires RAPIDAPI_KEY)
    if RAPIDAPI_KEY:
        try:
            bd = requests.get(
                "https://breachdirectory.p.rapidapi.com/",
                params={"func": "auto", "term": query},
                headers={
                    "x-rapidapi-host": "breachdirectory.p.rapidapi.com",
                    "x-rapidapi-key":  RAPIDAPI_KEY,
                },
                timeout=12,
            )
            if bd.status_code == 200:
                bd_data = bd.json()
                # Quota exceeded or error message
                if bd_data.get("message"):
                    result["breachdirectory_error"] = bd_data["message"]
                elif bd_data.get("success") and bd_data.get("result"):
                    for entry in bd_data["result"][:15]:
                        src = entry.get("sources", "BreachDirectory")
                        src_str = src if isinstance(src, str) else ", ".join(src)
                        result["results"].append({
                            "source":       "breachdirectory",
                            "url":          f"https://breachdirectory.org/?search={query}",
                            "raw_url":      None,
                            "title":        src_str,
                            "date":         None,
                            "repo":         entry.get("email"),
                            "sha1":         entry.get("sha1"),
                            "hash_password":entry.get("hash_password", False),
                            "has_password": bool(entry.get("password") or entry.get("sha1")),
                        })
                    result["sources"].append("breachdirectory")
                    result["breach_count"] = bd_data.get("found", 0)
        except Exception:
            pass

    # Source 5: GitHub code search (requires GITHUB_TOKEN)
    if GITHUB_TOKEN:
        try:
            gh_r = requests.get(
                f"https://api.github.com/search/code?q={quote_plus(query)}&per_page=5",
                headers={
                    "Authorization": f"Bearer {GITHUB_TOKEN}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "OsintPlus",
                },
                timeout=10,
            )
            if gh_r.status_code == 200:
                items = gh_r.json().get("items", [])
                for item in items[:5]:
                    result["results"].append({
                        "source":  "github",
                        "url":     item.get("html_url"),
                        "raw_url": None,
                        "title":   item.get("name"),
                        "date":    None,
                        "repo":    item.get("repository", {}).get("full_name"),
                    })
                if items:
                    result["sources"].append("github.com")
        except Exception:
            pass

    result["total"] = len(result["results"])
    result["links"] = {
        "dehashed":        f"https://www.dehashed.com/search?query={query}",
        "intelx":          f"https://intelx.io/?s={query}",
        "breachdirectory": f"https://breachdirectory.org/?search={query}",
        "leakcheck":       f"https://leakcheck.io/search?query={query}",
        "snusbase":        f"https://snusbase.com/",
    }

    # Hint about which keys are missing
    missing = []
    if is_email and not HIBP_API_KEY:
        missing.append("HIBP_API_KEY (email paste check — free at haveibeenpwned.com/API/Key)")
    if not INTELX_KEY:
        missing.append("INTELX_KEY (leak database — free at intelx.io)")
    if not RAPIDAPI_KEY:
        missing.append("RAPIDAPI_KEY (BreachDirectory — free at rapidapi.com/rohan-kumar1/api/breachdirectory)")
    if not GITHUB_TOKEN:
        missing.append("GITHUB_TOKEN (code search — free at github.com/settings/tokens)")
    result["missing_keys"] = missing

    return jsonify(result)


# ─────────────────────────────────────────────
# STATUS — check which tools are installed
# ─────────────────────────────────────────────
@app.route("/api/status")
def tool_status():
    tools = {}

    def _check_cmd(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def _check_import(mod):
        try:
            __import__(mod)
            return True
        except ImportError:
            return False

    tools["maigret"]      = _check_cmd([MAIGRET_EXE, "--version"])
    tools["holehe"]       = _check_import("holehe")
    tools["instaloader"]  = _check_import("instaloader")
    tools["toutatis"]     = _check_import("instaloader")   # toutatis uses instaloader impl
    tools["phonenumbers"] = _check_import("phonenumbers")
    tools["whois"]        = _check_import("whois")
    tools["requests"]     = _check_import("requests")
    tools["dnspython"]    = _check_import("dns.resolver")
    tools["hibp_key"]     = bool(HIBP_API_KEY)
    tools["intelx_key"]   = bool(INTELX_KEY)
    tools["rapidapi_key"] = bool(RAPIDAPI_KEY)
    tools["ipinfo_token"] = bool(IPINFO_TOKEN)
    tools["ig_session"]   = bool(INSTAGRAM_SESSIONID)
    tools["github_token"] = bool(GITHUB_TOKEN)

    return jsonify({"tools": tools})


if __name__ == "__main__":
    _debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    _host  = os.getenv("FLASK_HOST", "127.0.0.1")
    _port  = int(os.getenv("FLASK_PORT", "7171"))
    logger.info("Starting OsintPlus on %s:%d (debug=%s)", _host, _port, _debug)
    app.run(host=_host, port=_port, debug=_debug)
