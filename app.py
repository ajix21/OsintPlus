"""
OSINT Plus — Multi-Tool Open Source Intelligence Platform
Tools: maigret · holehe · ghunt · ipinfo · whois · iginfo · toutatis · hibp · telcek
"""
from flask import Flask, render_template, jsonify, request
import subprocess, json, os, re, hashlib, socket, time, sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

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

app = Flask(__name__)
app.secret_key = os.urandom(24)

IPINFO_TOKEN        = os.getenv("IPINFO_TOKEN", "")
HIBP_API_KEY        = os.getenv("HIBP_API_KEY", "")
INSTAGRAM_SESSIONID = os.getenv("INSTAGRAM_SESSIONID", "")

# ── In-memory cache for Instagram lookups ──────────────────────────────────
_ig_cache: dict = {}          # { "ig:<username>": (timestamp, data) }
_IG_CACHE_TTL = 300           # 5 minutes

def _ig_cache_get(key: str):
    entry = _ig_cache.get(key)
    if entry and (time.time() - entry[0]) < _IG_CACHE_TTL:
        return entry[1]
    return None

def _ig_cache_set(key: str, data: dict):
    _ig_cache[key] = (time.time(), data)

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

    # ipinfo.io
    e164 = result.get("e164", re.sub(r"[^\d+]", "", number))
    try:
        ip_url = f"https://ipinfo.io/{e164}/json"
        if IPINFO_TOKEN:
            ip_url += f"?token={IPINFO_TOKEN}"
        r = requests.get(ip_url, timeout=10)
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
        result["ip_address"] = ip
        result["resolves"]   = True
        result["sources"].append("dns")

        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
        if r.status_code == 200:
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
    _raw_sid  = data.get("sessionid") or INSTAGRAM_SESSIONID or ""
    sessionid = unquote(_raw_sid.strip())

    if not username:
        return jsonify({"error": "Username required"}), 400
    if not sessionid:
        return jsonify({"error": "Instagram sessionid required (set in .env atau kirim di request)"}), 400

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
    tools["toutatis"]     = _check_import("toutatis")
    tools["phonenumbers"] = _check_import("phonenumbers")
    tools["whois"]        = _check_import("whois")
    tools["requests"]     = _check_import("requests")
    tools["hibp_key"]     = bool(HIBP_API_KEY)
    tools["ipinfo_token"] = bool(IPINFO_TOKEN)
    tools["ig_session"]   = bool(INSTAGRAM_SESSIONID)

    return jsonify({"tools": tools})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7171, debug=True)
