#!/usr/bin/env python3
"""
CTF Web Fuzzer - Brute-Force & Parameter Fuzzing Utility
=========================================================
A modular, session-aware HTTP fuzzer for CTF web challenges.

Usage examples:
    python fuzzer.py -u http://target/login -w wordlist.txt -m POST -p "user=admin&pass=FUZZ"
    python fuzzer.py -u http://target/page?id=FUZZ -w nums.txt -fc 404
    python fuzzer.py -u http://target/FUZZ -w dirs.txt --mc 200,301,302
    python fuzzer.py -u http://target/api -w users.txt -m POST --json '{"user":"FUZZ"}' -fr "success"

Markers:
    FUZZ   - Replaced with each word from the wordlist
    FUZ2Z  - Replaced with words from a second wordlist (--wordlist2)
"""

import argparse
import json
import os
import re
import sys
import time
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] 'requests' is required: pip install requests")
    sys.exit(1)


# =====================================================================
# ANSI Colors (auto-disabled on non-TTY)
# =====================================================================
class C:
    _on = sys.stdout.isatty()
    RST = "\033[0m"   if _on else ""
    BLD = "\033[1m"    if _on else ""
    DIM = "\033[2m"    if _on else ""
    RED = "\033[91m"   if _on else ""
    GRN = "\033[92m"   if _on else ""
    YLW = "\033[93m"   if _on else ""
    BLU = "\033[94m"   if _on else ""
    MAG = "\033[95m"   if _on else ""
    CYN = "\033[96m"   if _on else ""
    WHT = "\033[97m"   if _on else ""
    BGG = "\033[42m"   if _on else ""


# =====================================================================
# CONFIGURATION DEFAULTS (override via CLI or edit directly)
# =====================================================================
DEFAULT_CONFIG = {
    "timeout":       10,
    "threads":       10,
    "delay":         0,       # seconds between requests (per-thread)
    "follow_redirects": True,
    "verify_ssl":    False,
    "max_retries":   2,
    "user_agent":    "Mozilla/5.0 (CTF-Fuzzer/1.0)",
    "proxy":         None,    # e.g. "http://127.0.0.1:8080" for Burp
}


# =====================================================================
# SESSION FACTORY
# =====================================================================
def build_session(config: dict, cookies: dict = None, headers: dict = None) -> requests.Session:
    """
    Create a persistent requests.Session with retry logic,
    custom headers, cookies, and optional proxy support.
    """
    session = requests.Session()

    # -- Retry strategy ------------------------------------------------
    retry = Retry(
        total=config["max_retries"],
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://",  adapter)
    session.mount("https://", adapter)

    # -- Headers -------------------------------------------------------
    session.headers["User-Agent"] = config["user_agent"]
    if headers:
        session.headers.update(headers)

    # -- Cookies -------------------------------------------------------
    if cookies:
        session.cookies.update(cookies)

    # -- Proxy ---------------------------------------------------------
    if config["proxy"]:
        session.proxies = {
            "http":  config["proxy"],
            "https": config["proxy"],
        }

    # -- SSL -----------------------------------------------------------
    session.verify = config["verify_ssl"]

    return session


# =====================================================================
# WORDLIST LOADER
# =====================================================================
def load_wordlist(path: str) -> list[str]:
    """
    Load a wordlist file, stripping blank lines and comments (#).
    Supports large files by reading line-by-line.
    """
    if not os.path.isfile(path):
        print(f"{C.RED}[!] Wordlist not found: {path}{C.RST}")
        sys.exit(1)

    words = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                words.append(stripped)

    print(f"{C.GRN}[+]{C.RST} Loaded {C.BLD}{len(words)}{C.RST} words from {C.CYN}{path}{C.RST}")
    return words


# =====================================================================
# RESPONSE ANALYSIS
# =====================================================================
def count_words(text: str) -> int:
    """Count whitespace-delimited words in response body."""
    return len(text.split())


def count_lines(text: str) -> int:
    """Count lines in response body."""
    return text.count("\n") + (1 if text else 0)


def count_chars(text: str) -> int:
    """Count characters in response body."""
    return len(text)


def matches_regex(text: str, pattern: str) -> bool:
    """Check if response body matches a regex pattern."""
    try:
        return bool(re.search(pattern, text, re.IGNORECASE))
    except re.error:
        return False


# =====================================================================
# FILTERS
# =====================================================================
class ResponseFilter:
    """
    Decides whether to SHOW or HIDE a response based on user criteria.

    Match filters (--mc, --ms, --mr, --mw, --ml): show ONLY matching.
    Filter filters (--fc, --fs, --fr, --fw, --fl): HIDE matching.

    If no match filters are set, everything is shown (minus filtered).
    """

    def __init__(self, args):
        # -- Match (whitelist) -----------------------------------------
        self.match_codes  = self._parse_int_list(args.mc)
        self.match_sizes  = self._parse_int_list(args.ms)
        self.match_words  = self._parse_int_list(args.mw)
        self.match_lines  = self._parse_int_list(args.ml)
        self.match_regex  = args.mr

        # -- Filter (blacklist) ----------------------------------------
        self.filter_codes = self._parse_int_list(args.fc)
        self.filter_sizes = self._parse_int_list(args.fs)
        self.filter_words = self._parse_int_list(args.fw)
        self.filter_lines = self._parse_int_list(args.fl)
        self.filter_regex = args.fr

        self.has_match = any([
            self.match_codes, self.match_sizes,
            self.match_words, self.match_lines,
            self.match_regex,
        ])

    @staticmethod
    def _parse_int_list(value: str | None) -> list[int]:
        """Parse comma-separated integers (e.g. '200,301,404')."""
        if not value:
            return []
        return [int(x.strip()) for x in value.split(",") if x.strip().isdigit()]

    def should_show(self, status: int, body: str) -> bool:
        """Return True if this response should be displayed."""
        size  = count_chars(body)
        words = count_words(body)
        lines = count_lines(body)

        # -- Blacklist checks (filter out) -----------------------------
        if self.filter_codes and status in self.filter_codes:
            return False
        if self.filter_sizes and size in self.filter_sizes:
            return False
        if self.filter_words and words in self.filter_words:
            return False
        if self.filter_lines and lines in self.filter_lines:
            return False
        if self.filter_regex and matches_regex(body, self.filter_regex):
            return False

        # -- Whitelist checks (match only) -----------------------------
        if self.has_match:
            matched = False
            if self.match_codes and status in self.match_codes:
                matched = True
            if self.match_sizes and size in self.match_sizes:
                matched = True
            if self.match_words and words in self.match_words:
                matched = True
            if self.match_lines and lines in self.match_lines:
                matched = True
            if self.match_regex and matches_regex(body, self.match_regex):
                matched = True
            return matched

        return True


# =====================================================================
# REQUEST ENGINE
# =====================================================================
def substitute(template: str, word: str, word2: str = "") -> str:
    """Replace FUZZ/FUZ2Z markers in a string."""
    result = template.replace("FUZZ", word)
    if word2:
        result = result.replace("FUZ2Z", word2)
    return result


def send_request(
    session: requests.Session,
    method: str,
    url: str,
    word: str,
    word2: str = "",
    post_data: str = None,
    json_body: str = None,
    extra_headers: dict = None,
    config: dict = None,
) -> dict:
    """
    Send a single fuzzed HTTP request and return a result dict.

    Returns:
        {
            "word": str,
            "url": str,
            "status": int,
            "length": int,
            "words": int,
            "lines": int,
            "body": str,
            "headers": dict,
            "time_ms": float,
            "error": str | None,
        }
    """
    config = config or DEFAULT_CONFIG
    fuzzed_url = substitute(url, word, word2)

    result = {
        "word":    word,
        "url":     fuzzed_url,
        "status":  0,
        "length":  0,
        "words":   0,
        "lines":   0,
        "body":    "",
        "headers": {},
        "time_ms": 0,
        "error":   None,
    }

    # -- Build kwargs --------------------------------------------------
    kwargs = {
        "timeout": config["timeout"],
        "allow_redirects": config["follow_redirects"],
    }

    if extra_headers:
        fuzzed_headers = {k: substitute(v, word, word2) for k, v in extra_headers.items()}
        kwargs["headers"] = fuzzed_headers

    # -- Body (POST/PUT/PATCH) -----------------------------------------
    if post_data:
        fuzzed_data = substitute(post_data, word, word2)
        # Check if content-type suggests form data or raw
        content_type = (extra_headers or {}).get("Content-Type", "")
        if "json" in content_type:
            try:
                kwargs["json"] = json.loads(fuzzed_data)
            except json.JSONDecodeError:
                kwargs["data"] = fuzzed_data
        else:
            kwargs["data"] = fuzzed_data

    elif json_body:
        fuzzed_json = substitute(json_body, word, word2)
        try:
            kwargs["json"] = json.loads(fuzzed_json)
        except json.JSONDecodeError:
            result["error"] = "Invalid JSON body"
            return result

    # -- Send ----------------------------------------------------------
    try:
        start = time.time()
        resp = session.request(method.upper(), fuzzed_url, **kwargs)
        elapsed = (time.time() - start) * 1000

        result["status"]  = resp.status_code
        result["body"]    = resp.text
        result["headers"] = dict(resp.headers)
        result["length"]  = count_chars(resp.text)
        result["words"]   = count_words(resp.text)
        result["lines"]   = count_lines(resp.text)
        result["time_ms"] = round(elapsed, 1)

    except requests.exceptions.ConnectionError:
        result["error"] = "Connection refused"
    except requests.exceptions.Timeout:
        result["error"] = "Timeout"
    except requests.exceptions.TooManyRedirects:
        result["error"] = "Too many redirects"
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)[:80]

    return result


# =====================================================================
# OUTPUT FORMATTING
# =====================================================================
def status_color(code: int) -> str:
    """Color-code HTTP status."""
    if 200 <= code < 300:
        return C.GRN
    elif 300 <= code < 400:
        return C.BLU
    elif 400 <= code < 500:
        return C.YLW
    elif code >= 500:
        return C.RED
    return C.DIM


def print_result(result: dict, verbose: bool = False):
    """Print a single fuzz result line."""
    if result["error"]:
        print(f"  {C.RED}ERR{C.RST}  {result['word']:<30}  {C.DIM}{result['error']}{C.RST}")
        return

    sc = status_color(result["status"])
    line = (
        f"  {sc}{result['status']}{C.RST}"
        f"  {result['word']:<30}"
        f"  {C.DIM}[Size: {result['length']}"
        f"  Words: {result['words']}"
        f"  Lines: {result['lines']}"
        f"  Time: {result['time_ms']}ms]{C.RST}"
    )
    print(line)

    if verbose and result["body"]:
        preview = result["body"][:300].replace("\n", "\\n")
        print(f"      {C.DIM}{preview}{C.RST}")


def print_banner(args, wordcount: int):
    """Print the run configuration banner."""
    print(f"""
{C.CYN}{C.BLD}
   ___ _   _ ___________ ___
  |  _| | | |___  /___  / _ \\
  | |_| | | |  / /   / /  __/
  |  _| |_| | / /__ / /\\__ \\
  |_|  \\___/ /_____/_/ |___/
{C.RST}{C.DIM}  CTF Web Fuzzer - Brute-Force & Parameter Fuzzing{C.RST}
""")
    print(f"  {C.DIM}Target  :{C.RST}  {C.BLD}{args.url}{C.RST}")
    print(f"  {C.DIM}Method  :{C.RST}  {args.method.upper()}")
    print(f"  {C.DIM}Words   :{C.RST}  {wordcount}")
    print(f"  {C.DIM}Threads :{C.RST}  {args.threads}")
    if args.data:
        print(f"  {C.DIM}Data    :{C.RST}  {args.data}")
    if args.json_body:
        print(f"  {C.DIM}JSON    :{C.RST}  {args.json_body}")
    if args.mc:
        print(f"  {C.DIM}Match   :{C.RST}  codes={args.mc}")
    if args.fc:
        print(f"  {C.DIM}Filter  :{C.RST}  codes={args.fc}")
    if args.mr:
        print(f"  {C.DIM}Match-Re:{C.RST}  {args.mr}")
    if args.fr:
        print(f"  {C.DIM}Filt-Re :{C.RST}  {args.fr}")
    if args.proxy:
        print(f"  {C.DIM}Proxy   :{C.RST}  {args.proxy}")
    print(f"\n  {C.DIM}{'=' * 68}{C.RST}")
    print(f"  {C.BLD}{'Status':<6}  {'Payload':<30}  {'Details'}{C.RST}")
    print(f"  {C.DIM}{'=' * 68}{C.RST}")


def print_summary(total: int, shown: int, errors: int, elapsed: float):
    """Print the run summary."""
    print(f"\n  {C.DIM}{'=' * 68}{C.RST}")
    print(f"  {C.BLD}Completed:{C.RST} {total} requests"
          f"  |  {C.GRN}Shown: {shown}{C.RST}"
          f"  |  {C.RED}Errors: {errors}{C.RST}"
          f"  |  {C.DIM}Time: {elapsed:.1f}s{C.RST}")
    print()


# =====================================================================
# MAIN FUZZER LOOP
# =====================================================================
def run_fuzzer(args):
    """Main entry: load wordlist, configure session, fuzz target."""

    # -- Load wordlist(s) ----------------------------------------------
    wordlist = load_wordlist(args.wordlist)
    wordlist2 = load_wordlist(args.wordlist2) if args.wordlist2 else [""]

    # -- Parse extra headers -------------------------------------------
    extra_headers = {}
    if args.headers:
        for h in args.headers:
            if ":" in h:
                key, val = h.split(":", 1)
                extra_headers[key.strip()] = val.strip()

    # -- Parse cookies -------------------------------------------------
    cookies = {}
    if args.cookies:
        for c in args.cookies:
            if "=" in c:
                key, val = c.split("=", 1)
                cookies[key.strip()] = val.strip()

    # -- Build config --------------------------------------------------
    config = dict(DEFAULT_CONFIG)
    config["timeout"]   = args.timeout
    config["threads"]   = args.threads
    config["delay"]     = args.delay
    config["proxy"]     = args.proxy
    config["verify_ssl"] = not args.no_ssl_verify
    config["follow_redirects"] = not args.no_follow

    if args.proxy:
        config["proxy"] = args.proxy

    # -- Build session -------------------------------------------------
    session = build_session(config, cookies=cookies, headers=extra_headers)

    # -- Authentication (if provided) ----------------------------------
    if args.auth:
        parts = args.auth.split(":", 1)
        if len(parts) == 2:
            session.auth = (parts[0], parts[1])
            print(f"{C.GRN}[+]{C.RST} Basic auth: {parts[0]}:{'*' * len(parts[1])}")

    # -- Response filter -----------------------------------------------
    resp_filter = ResponseFilter(args)

    # -- Prepare word pairs (for dual wordlists) -----------------------
    word_pairs = [(w1, w2) for w1 in wordlist for w2 in wordlist2]
    total = len(word_pairs)

    # -- Banner --------------------------------------------------------
    print_banner(args, total)

    # -- Run -----------------------------------------------------------
    shown = 0
    errors = 0
    start_time = time.time()
    output_lines = []

    def fuzz_one(pair):
        """Process a single word pair."""
        w1, w2 = pair
        if config["delay"] > 0:
            time.sleep(config["delay"])
        return send_request(
            session=session,
            method=args.method,
            url=args.url,
            word=w1,
            word2=w2,
            post_data=args.data,
            json_body=args.json_body,
            extra_headers=extra_headers,
            config=config,
        )

    try:
        with ThreadPoolExecutor(max_workers=config["threads"]) as pool:
            futures = {pool.submit(fuzz_one, pair): pair for pair in word_pairs}

            for future in as_completed(futures):
                result = future.result()

                if result["error"]:
                    errors += 1
                    if args.verbose:
                        print_result(result, verbose=args.verbose)
                    continue

                if resp_filter.should_show(result["status"], result["body"]):
                    shown += 1
                    print_result(result, verbose=args.verbose)

                    # Save to output file if requested
                    if args.output:
                        output_lines.append(
                            f"{result['status']}\t{result['word']}\t"
                            f"{result['length']}\t{result['words']}\t"
                            f"{result['lines']}\t{result['url']}"
                        )

    except KeyboardInterrupt:
        print(f"\n{C.YLW}[!] Interrupted by user.{C.RST}")

    elapsed = time.time() - start_time

    # -- Output file ---------------------------------------------------
    if args.output and output_lines:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("Status\tWord\tLength\tWords\tLines\tURL\n")
            f.write("\n".join(output_lines) + "\n")
        print(f"\n{C.GRN}[+]{C.RST} Results saved to {C.CYN}{args.output}{C.RST}")

    # -- Summary -------------------------------------------------------
    print_summary(total, shown, errors, elapsed)


# =====================================================================
# CLI ARGUMENT PARSER
# =====================================================================
def parse_args():
    parser = argparse.ArgumentParser(
        description="CTF Web Fuzzer - Brute-force & parameter fuzzing utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          Directory brute-force:
            python fuzzer.py -u http://target/FUZZ -w dirs.txt --mc 200,301

          Login brute-force (POST form):
            python fuzzer.py -u http://target/login -w passwords.txt \\
                -m POST -p "username=admin&password=FUZZ" \\
                -fr "Invalid" --mc 200,302

          API parameter fuzzing (JSON):
            python fuzzer.py -u http://target/api/user \\
                -w ids.txt -m POST \\
                --json '{"id": "FUZZ"}' --mc 200

          Header fuzzing:
            python fuzzer.py -u http://target/admin \\
                -w tokens.txt -H "Authorization: Bearer FUZZ" --mc 200

          With proxy (Burp Suite):
            python fuzzer.py -u http://target/FUZZ -w dirs.txt \\
                --proxy http://127.0.0.1:8080

          Dual wordlists (user:pass):
            python fuzzer.py -u http://target/login \\
                -w users.txt -w2 passwords.txt \\
                -m POST -p "user=FUZZ&pass=FUZ2Z"

          Filter by regex (hide "Not Found" pages):
            python fuzzer.py -u http://target/FUZZ -w dirs.txt \\
                -fr "Not Found|404|does not exist"

          Save results to file:
            python fuzzer.py -u http://target/FUZZ -w dirs.txt \\
                --mc 200 -o results.txt
        """),
    )

    # -- Required ------------------------------------------------------
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL (use FUZZ as placeholder)")
    parser.add_argument("-w", "--wordlist", required=True,
                        help="Path to wordlist file")

    # -- Request options -----------------------------------------------
    req = parser.add_argument_group("Request Options")
    req.add_argument("-m", "--method", default="GET",
                     choices=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
                     help="HTTP method (default: GET)")
    req.add_argument("-p", "--data", default=None,
                     help="POST body (use FUZZ as placeholder)")
    req.add_argument("--json", dest="json_body", default=None,
                     help="JSON body (use FUZZ as placeholder)")
    req.add_argument("-H", "--header", dest="headers", action="append", default=[],
                     help="Custom header as 'Key: Value' (repeatable)")
    req.add_argument("-b", "--cookie", dest="cookies", action="append", default=[],
                     help="Cookie as 'name=value' (repeatable)")
    req.add_argument("--auth", default=None,
                     help="Basic auth as 'user:pass'")
    req.add_argument("--proxy", default=None,
                     help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    req.add_argument("--no-follow", action="store_true",
                     help="Do not follow redirects")
    req.add_argument("--no-ssl-verify", action="store_true",
                     help="Disable SSL certificate verification")

    # -- Wordlists -----------------------------------------------------
    wl = parser.add_argument_group("Wordlist Options")
    wl.add_argument("-w2", "--wordlist2", default=None,
                    help="Second wordlist (use FUZ2Z as placeholder)")

    # -- Match filters (whitelist: show only these) --------------------
    mf = parser.add_argument_group("Match Filters (show only matching responses)")
    mf.add_argument("--mc", default=None,
                    help="Match HTTP status codes (comma-separated, e.g. 200,301)")
    mf.add_argument("--ms", default=None,
                    help="Match response size in chars (comma-separated)")
    mf.add_argument("--mw", default=None,
                    help="Match word count (comma-separated)")
    mf.add_argument("--ml", default=None,
                    help="Match line count (comma-separated)")
    mf.add_argument("--mr", default=None,
                    help="Match response body regex")

    # -- Filter (blacklist: hide these) --------------------------------
    ff = parser.add_argument_group("Filter (hide matching responses)")
    ff.add_argument("--fc", default=None,
                    help="Filter HTTP status codes (comma-separated, e.g. 404,500)")
    ff.add_argument("--fs", default=None,
                    help="Filter response size in chars (comma-separated)")
    ff.add_argument("--fw", default=None,
                    help="Filter word count (comma-separated)")
    ff.add_argument("--fl", default=None,
                    help="Filter line count (comma-separated)")
    ff.add_argument("--fr", default=None,
                    help="Filter response body regex")

    # -- Performance ---------------------------------------------------
    perf = parser.add_argument_group("Performance")
    perf.add_argument("-t", "--threads", type=int, default=10,
                      help="Number of concurrent threads (default: 10)")
    perf.add_argument("--timeout", type=int, default=10,
                      help="Request timeout in seconds (default: 10)")
    perf.add_argument("--delay", type=float, default=0,
                      help="Delay between requests per thread in seconds (default: 0)")

    # -- Output --------------------------------------------------------
    out = parser.add_argument_group("Output")
    out.add_argument("-o", "--output", default=None,
                     help="Save matching results to a file (TSV format)")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="Show response body preview and errors")

    return parser.parse_args()


# =====================================================================
# ENTRY POINT
# =====================================================================
if __name__ == "__main__":
    args = parse_args()
    run_fuzzer(args)
