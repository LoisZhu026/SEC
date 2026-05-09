"""
SEC EDGAR Cybersecurity Disclosure Scraper - Proof of Concept
Target: Microsoft (CIK: 0000789019)
Purpose: Validate the full pipeline before batch processing
"""

import requests
import requests.adapters
import ssl
import certifi
import time
import re
import warnings
import csv
import os
from datetime import datetime, date
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
USER_AGENT = "Lois Research Project (Luoyi.Zhu23@student.xjtlu.edu.cn)"
SLEEP = 0.15  # SEC rate limit: max 10 req/s

TEST_CIK = "0000789019"
TEST_TICKER = "MSFT"
CUTOFF_DATE = date(2023, 12, 1)


# ─────────────────────────────────────────────
# TLS FIX for Python 3.14 on macOS
# ─────────────────────────────────────────────
class TLSAdapter(requests.adapters.HTTPAdapter):
    """Force TLS with certifi CA bundle — fixes SSL EOF on Python 3.14"""
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(certifi.where())
        ctx.set_ciphers("DEFAULT")
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


_SESSION = requests.Session()
_SESSION.mount("https://", TLSAdapter())
_SESSION.headers.update({"User-Agent": USER_AGENT})


def get_with_retry(url, retries=3):
    """带重试的 GET 请求"""
    for attempt in range(retries):
        try:
            resp = _SESSION.get(url, timeout=20)
            resp.raise_for_status()
            time.sleep(SLEEP)
            return resp
        except requests.RequestException as e:
            print(f"  [WARN] Attempt {attempt+1} failed: {e}")
            time.sleep(1.5)
    return None


# ─────────────────────────────────────────────
# STEP 1: 获取公司公告目录
# ─────────────────────────────────────────────
def fetch_submissions(cik_10):
    url = f"https://data.sec.gov/submissions/CIK{cik_10}.json"
    print(f"\n[Step 1] Fetching submissions for CIK {cik_10}...")
    resp = get_with_retry(url)
    if not resp:
        raise RuntimeError(f"Failed to fetch submissions for {cik_10}")
    data = resp.json()
    # Correct path: data["filings"]["recent"]
    recent = data.get("filings", {}).get("recent", {})
    return recent


# ─────────────────────────────────────────────
# STEP 2: 查找 8-K Item 1.05（用 items 字段直接过滤）
# ─────────────────────────────────────────────
def find_8k_item105(recent):
    """
    利用 SEC JSON 中的 items 字段直接过滤，无需下载每份 HTML。
    返回列表: [{"filingDate", "accessionNumber", "accessionNoDash", "primaryDocument"}, ...]
    """
    forms        = recent.get("form", [])
    dates        = recent.get("filingDate", [])
    accessions   = recent.get("accessionNumber", [])
    primary_docs = recent.get("primaryDocument", [])
    items_field  = recent.get("items", [])

    results = []
    print(f"\n[Step 2] Scanning for 8-K filings with Item 1.05 after {CUTOFF_DATE}...")

    for i, form in enumerate(forms):
        if form != "8-K":
            continue
        filing_date = datetime.strptime(dates[i], "%Y-%m-%d").date()
        if filing_date < CUTOFF_DATE:
            continue

        # items 字段示例: "1.05,7.01,9.01"
        item_str = items_field[i] if i < len(items_field) else ""
        item_list = [x.strip() for x in item_str.split(",")]

        if "1.05" in item_list:
            print(f"  ✓ {dates[i]}  {accessions[i]}  items={item_str}")
            results.append({
                "filingDate":      filing_date,
                "accessionNumber": accessions[i],
                "accessionNoDash": accessions[i].replace("-", ""),
                "primaryDocument": primary_docs[i],
            })

    print(f"\n  → Found {len(results)} 8-K(s) with Item 1.05")
    return results


# ─────────────────────────────────────────────
# STEP 3: 匹配最近的 10-K
# ─────────────────────────────────────────────
def find_preceding_10k(recent, event_date):
    forms        = recent.get("form", [])
    dates        = recent.get("filingDate", [])
    accessions   = recent.get("accessionNumber", [])
    primary_docs = recent.get("primaryDocument", [])

    best = None
    best_date = None

    for i, form in enumerate(forms):
        if form != "10-K":
            continue
        filing_date = datetime.strptime(dates[i], "%Y-%m-%d").date()
        if filing_date >= event_date:
            continue
        if best_date is None or filing_date > best_date:
            best_date = filing_date
            best = {
                "filingDate":      filing_date,
                "accessionNumber": accessions[i],
                "accessionNoDash": accessions[i].replace("-", ""),
                "primaryDocument": primary_docs[i],
            }

    if best:
        print(f"\n[Step 3] Matched 10-K: {best['accessionNumber']} ({best['filingDate']})")
    else:
        print(f"\n[Step 3] No 10-K found before {event_date}")
    return best


# ─────────────────────────────────────────────
# STEP 4a: 解析 8-K — Item 1.05 文本 + 事件日期
# ─────────────────────────────────────────────
def fetch_and_parse_8k(cik_10, eight_k_info):
    cik_num = str(int(cik_10))
    url = (
        f"https://www.sec.gov/Archives/edgar/data/{cik_num}/"
        f"{eight_k_info['accessionNoDash']}/{eight_k_info['primaryDocument']}"
    )
    print(f"\n[Step 4a] Fetching 8-K: {url}")
    resp = get_with_retry(url)
    if not resp:
        return "", None

    soup = BeautifulSoup(resp.text, "lxml")
    # Join with space to handle iXBRL word-splitting across tags
    raw_text = soup.get_text(separator=" ")
    text = re.sub(r"[ \t]+", " ", raw_text)

    # ── 提取 Item 1.05 段落 ──
    pattern = re.compile(
        r"(Item\s+1\.05\s*\.?\s*Material\s+Cybersecurity\s+Incidents?.*?)"
        r"(?=Item\s+\d+\.\d+|\Z)",
        re.IGNORECASE | re.DOTALL
    )
    match = pattern.search(text)
    item105_text = ""
    if match:
        item105_text = match.group(1).strip()
        item105_text = re.sub(r"\s{3,}", "\n\n", item105_text)

    # ── 提取事件日期 ──
    incident_date = None
    date_pattern = re.compile(
        r"Date of (?:Report|earliest event)[^\n]*?[:\s]+"
        r"([A-Za-z]+ \d{1,2},?\s*\d{4}|\d{1,2}/\d{1,2}/\d{4}|\d{4}-\d{2}-\d{2})",
        re.IGNORECASE
    )
    date_match = date_pattern.search(text)
    if date_match:
        raw = date_match.group(1).strip().replace("  ", " ")
        for fmt in ("%B %d, %Y", "%B %d %Y", "%m/%d/%Y", "%Y-%m-%d"):
            try:
                incident_date = datetime.strptime(raw, fmt).date()
                break
            except ValueError:
                continue

    return item105_text, incident_date


# ─────────────────────────────────────────────
# STEP 4b: 解析 10-K — Item 1C + Item 1A cyber
# ─────────────────────────────────────────────
def fetch_and_parse_10k(cik_10, ten_k_info):
    cik_num = str(int(cik_10))
    url = (
        f"https://www.sec.gov/Archives/edgar/data/{cik_num}/"
        f"{ten_k_info['accessionNoDash']}/{ten_k_info['primaryDocument']}"
    )
    print(f"\n[Step 4b] Fetching 10-K: {url}")
    resp = get_with_retry(url)
    if not resp:
        return "", ""

    soup = BeautifulSoup(resp.text, "lxml")
    # Join with space to handle iXBRL word-splitting across tags
    raw_text = soup.get_text(separator=" ")
    text = re.sub(r"[ \t]+", " ", raw_text)

    # ── Item 1C (Cybersecurity) ──
    # Note: Item 1C was only required after Dec 2023 rules.
    # Pre-2024 10-Ks may not have this section — that is expected.
    item1c_pattern = re.compile(
        r"(ITEM\s+1C\.?\s*CYBERSECURITY.*?)"
        r"(?=ITEM\s+\d+[A-Z]?\.|\Z)",
        re.IGNORECASE | re.DOTALL
    )
    m1c = item1c_pattern.search(text)
    item1c_text = ""
    if m1c:
        item1c_text = m1c.group(1).strip()
        item1c_text = re.sub(r"\s{3,}", "\n\n", item1c_text)

    # ── Item 1A — cyber 相关段落 ──
    # iXBRL format: "ITEM 1A. RIS K FACTORS" may be split across tags.
    # There are TWO occurrences: table of contents (short) and body (long).
    # Use the LAST match which is the actual body section.
    item1a_cyber_text = ""
    all_1a = list(re.finditer(
        r"ITEM\s+1A[.\s]*(?:RIS\s*K\s*FACTORS|RISK\s+FACTORS)",
        text, re.IGNORECASE
    ))
    if all_1a:
        # Use the last occurrence (body, not TOC)
        body_start = all_1a[-1].end()
        # Find end: next ITEM 1B
        end_match = re.search(r"ITEM\s+1B", text[body_start:], re.IGNORECASE)
        body_end = body_start + end_match.start() if end_match else len(text)
        item1a_section = text[body_start:body_end]

        # Split on 3+ whitespace chars (paragraph breaks in iXBRL plain text)
        paragraphs = re.split(r"\s{3,}", item1a_section)
        cyber_paras = [
            p.strip() for p in paragraphs
            if re.search(r"cyber", p, re.IGNORECASE) and len(p.strip()) > 80
        ]
        item1a_cyber_text = "\n\n".join(cyber_paras)

    return item1c_text, item1a_cyber_text


# ─────────────────────────────────────────────
# MAIN PoC
# ─────────────────────────────────────────────
def run_poc():
    print("=" * 60)
    print(f"SEC EDGAR PoC — {TEST_TICKER} (CIK: {TEST_CIK})")
    print("=" * 60)

    # Step 1
    recent = fetch_submissions(TEST_CIK)

    # Step 2
    eight_k_list = find_8k_item105(recent)

    if not eight_k_list:
        print("\n[RESULT] No qualifying 8-K found for this company.")
        return

    # 只处理第一条（PoC 验证用）
    eight_k = eight_k_list[0]
    print(f"\n→ Processing: {eight_k['accessionNumber']} ({eight_k['filingDate']})")

    # Step 4a
    item105_text, incident_date = fetch_and_parse_8k(TEST_CIK, eight_k)
    filing_date = eight_k["filingDate"]
    disclosure_lag = (filing_date - incident_date).days if incident_date else None

    print(f"\n{'─'*50}")
    print(f"8-K Filing Date  : {filing_date}")
    print(f"8-K Incident Date: {incident_date}")
    print(f"Disclosure Lag   : {disclosure_lag} days")
    print(f"\n[8-K Item 1.05 — first 200 chars]")
    print(repr(item105_text[:200]) if item105_text else "  ⚠ NOT FOUND")

    # Step 3
    ten_k_info = find_preceding_10k(recent, filing_date)
    if not ten_k_info:
        print("\n[WARN] No preceding 10-K found.")
        return

    # Step 4b
    item1c_text, item1a_cyber_text = fetch_and_parse_10k(TEST_CIK, ten_k_info)

    print(f"\n{'─'*50}")
    print(f"10-K Filing Date : {ten_k_info['filingDate']}")
    print(f"\n[10-K Item 1C — first 200 chars]")
    print(repr(item1c_text[:200]) if item1c_text else "  ⚠ NOT FOUND")
    print(f"\n[10-K Item 1A Cyber Paragraphs — first 200 chars]")
    print(repr(item1a_cyber_text[:200]) if item1a_cyber_text else "  ⚠ NOT FOUND")

    # ── 导出 CSV ──
    output_path = os.path.join(os.path.dirname(__file__), "SEC_Cybersecurity_Data_PoC.csv")
    row = {
        "CIK":               TEST_CIK,
        "Ticker":            TEST_TICKER,
        "8K_Filing_Date":    filing_date,
        "8K_Incident_Date":  incident_date,
        "Disclosure_Lag":    disclosure_lag,
        "8K_Item1.05_Text":  item105_text,
        "10K_Filing_Date":   ten_k_info["filingDate"],
        "10K_Item1C_Text":   item1c_text,
        "10K_Item1A_Text":   item1a_cyber_text,
    }
    fieldnames = list(row.keys())
    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerow(row)

    print(f"\n{'='*60}")
    print(f"PoC Complete. CSV saved to:")
    print(f"  {output_path}")
    print("=" * 60)


if __name__ == "__main__":
    run_poc()
