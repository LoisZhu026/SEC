"""Collect SEC cybersecurity incident disclosures and preceding 10-K context.

The script supports a one-company validation run and resumable batch collection.
It uses only public SEC EDGAR endpoints; no commercial API key is required.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import ssl
import time
import warnings
from datetime import date, datetime
from pathlib import Path
from typing import Any, Iterable

import certifi
import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


SEC_SUBMISSIONS_URL = "https://data.sec.gov/submissions"
SEC_ARCHIVES_URL = "https://www.sec.gov/Archives/edgar/data"
DEFAULT_CUTOFF = date(2023, 12, 18)
DEFAULT_SLEEP_SECONDS = 0.15

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

INCIDENT_FIELDS = [
    "CIK",
    "Ticker",
    "Company",
    "8K_Accession",
    "8K_Filing_Date",
    "8K_Reported_Event_Date",
    "Disclosure_Lag_Days",
    "8K_URL",
    "8K_Item1.05_Text",
    "10K_Accession",
    "10K_Filing_Date",
    "10K_URL",
    "10K_Item1C_Text",
    "10K_Item1A_Cyber_Text",
    "Extraction_Status",
]

AUDIT_FIELDS = [
    "CIK",
    "Ticker",
    "Company",
    "Status",
    "Item1.05_Filings_Found",
    "Rows_Written",
    "Error",
]


class TLSAdapter(HTTPAdapter):
    """Use certifi's trust store on Python installations with TLS issues."""

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        context = ssl.create_default_context(cafile=certifi.where())
        kwargs["ssl_context"] = context
        super().init_poolmanager(*args, **kwargs)


class SecClient:
    """Small EDGAR client with retries and an explicit request interval."""

    def __init__(
        self,
        user_agent: str,
        sleep_seconds: float = DEFAULT_SLEEP_SECONDS,
        timeout_seconds: float = 30.0,
    ) -> None:
        if not user_agent.strip():
            raise ValueError("A descriptive SEC user agent is required.")

        retry = Retry(
            total=4,
            connect=4,
            read=4,
            status=4,
            backoff_factor=0.8,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET",),
            respect_retry_after_header=True,
        )
        adapter = TLSAdapter(max_retries=retry)
        self.session = requests.Session()
        self.session.mount("https://", adapter)
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept-Encoding": "gzip, deflate",
            }
        )
        self.sleep_seconds = max(sleep_seconds, 0.11)
        self.timeout_seconds = timeout_seconds

    def get_json(self, url: str) -> dict[str, Any]:
        response = self.session.get(url, timeout=self.timeout_seconds)
        response.raise_for_status()
        time.sleep(self.sleep_seconds)
        return response.json()

    def get_text(self, url: str) -> str:
        response = self.session.get(url, timeout=self.timeout_seconds)
        response.raise_for_status()
        time.sleep(self.sleep_seconds)
        return response.text


def parse_date(value: Any) -> date | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y", "%B %d, %Y", "%B %d %Y"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def format_cik(value: Any) -> str:
    """Normalize SEC CIKs, including Excel-style values such as ``789019.0``."""

    text = str(value).strip()
    if re.fullmatch(r"\d+\.0+", text):
        text = text.split(".", 1)[0]
    if not text.isdigit():
        raise ValueError(f"Invalid CIK: {value!r}")
    if len(text) > 10:
        raise ValueError(f"CIK has more than 10 digits: {value!r}")
    return text.zfill(10)


def _field(row: dict[str, Any], *names: str) -> str:
    lowered = {str(key).lower(): value for key, value in row.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value is not None:
            return str(value).strip()
    return ""


def load_company_universe(
    input_path: Path,
    cutoff: date,
    *,
    include_inactive: bool = False,
    skip: int = 0,
    limit: int | None = None,
) -> list[dict[str, str]]:
    """Load, filter, and deduplicate a CIK universe before applying skip/limit."""

    companies: list[dict[str, str]] = []
    seen: set[str] = set()
    with input_path.open(newline="", encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            raw_cik = _field(row, "cik")
            if not raw_cik:
                continue
            try:
                cik = format_cik(raw_cik)
            except ValueError:
                continue

            end_text = _field(row, "timeLinkEnd_d", "end_date")
            end_date = parse_date(end_text)
            if not include_inactive and end_date is not None and end_date < cutoff:
                continue
            if cik in seen:
                continue

            seen.add(cik)
            companies.append(
                {
                    "CIK": cik,
                    "Ticker": _field(row, "tic", "ticker"),
                    "Company": _field(row, "conm", "company", "name"),
                }
            )

    selected = companies[max(skip, 0) :]
    if limit is not None:
        selected = selected[: max(limit, 0)]
    return selected


def merge_recent_filings(*tables: dict[str, Any]) -> dict[str, list[Any]]:
    keys = {key for table in tables for key, value in table.items() if isinstance(value, list)}
    merged: dict[str, list[Any]] = {key: [] for key in keys}
    for table in tables:
        row_count = max((len(value) for value in table.values() if isinstance(value, list)), default=0)
        for index in range(row_count):
            for key in keys:
                values = table.get(key, [])
                merged[key].append(values[index] if index < len(values) else "")
    return merged


def fetch_filings(client: SecClient, cik: str, cutoff: date) -> dict[str, list[Any]]:
    """Fetch recent submissions and any supplemental file overlapping the cutoff."""

    payload = client.get_json(f"{SEC_SUBMISSIONS_URL}/CIK{cik}.json")
    filings = payload.get("filings", {})
    tables = [filings.get("recent", {})]
    for descriptor in filings.get("files", []):
        filing_to = parse_date(descriptor.get("filingTo"))
        if filing_to is not None and filing_to < cutoff:
            continue
        name = descriptor.get("name")
        if name:
            tables.append(client.get_json(f"{SEC_SUBMISSIONS_URL}/{name}"))
    return merge_recent_filings(*tables)


def _filing_at(recent: dict[str, list[Any]], index: int) -> dict[str, Any] | None:
    try:
        filing_date = parse_date(recent.get("filingDate", [])[index])
        accession = str(recent.get("accessionNumber", [])[index])
        primary_document = str(recent.get("primaryDocument", [])[index])
    except IndexError:
        return None
    if filing_date is None or not accession or not primary_document:
        return None
    return {
        "filingDate": filing_date,
        "accessionNumber": accession,
        "accessionNoDash": accession.replace("-", ""),
        "primaryDocument": primary_document,
    }


def find_item105_filings(
    recent: dict[str, list[Any]], cutoff: date
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    forms = recent.get("form", [])
    items = recent.get("items", [])
    for index, form in enumerate(forms):
        if str(form).upper() not in {"8-K", "8-K/A"}:
            continue
        filing = _filing_at(recent, index)
        if filing is None or filing["filingDate"] < cutoff:
            continue
        item_tokens = {
            token.strip()
            for token in str(items[index] if index < len(items) else "").split(",")
        }
        if "1.05" in item_tokens:
            results.append(filing)
    return sorted(results, key=lambda item: item["filingDate"])


def find_preceding_10k(
    recent: dict[str, list[Any]], event_filing_date: date
) -> dict[str, Any] | None:
    candidates: list[dict[str, Any]] = []
    for index, form in enumerate(recent.get("form", [])):
        if str(form).upper() not in {"10-K", "10-K/A"}:
            continue
        filing = _filing_at(recent, index)
        if filing is not None and filing["filingDate"] < event_filing_date:
            candidates.append(filing)
    return max(candidates, key=lambda item: item["filingDate"], default=None)


def filing_url(cik: str, filing: dict[str, Any]) -> str:
    return (
        f"{SEC_ARCHIVES_URL}/{int(cik)}/{filing['accessionNoDash']}/"
        f"{filing['primaryDocument']}"
    )


def document_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")
    for node in soup(["script", "style", "noscript"]):
        node.decompose()
    lines = [re.sub(r"\s+", " ", value).strip() for value in soup.stripped_strings]
    return "\n".join(line for line in lines if line)


def _longest_section(text: str, start_pattern: str, end_pattern: str) -> str:
    closed_candidates: list[str] = []
    open_candidates: list[str] = []
    flags = re.IGNORECASE | re.MULTILINE
    for start in re.finditer(start_pattern, text, flags=flags):
        following = text[start.end() :]
        end = re.search(end_pattern, following, flags=flags)
        candidate = text[
            start.start() : start.end() + (end.start() if end else len(following))
        ]
        candidate = re.sub(r"[ \t]+", " ", candidate).strip()
        if candidate:
            (closed_candidates if end else open_candidates).append(candidate)
    candidates = closed_candidates or open_candidates
    return max(candidates, key=len, default="")


def extract_item105_text(text: str) -> str:
    return _longest_section(
        text,
        r"^\s*item\s+1\.05\b(?:\s*\.?\s*material\s+cybersecurity\s+incidents?)?",
        r"^\s*item\s+(?!1\.05\b)\d+\.\d+\b",
    )


def extract_reported_event_date(text: str) -> date | None:
    match = re.search(
        r"Date\s+of\s+(?:Report|earliest\s+event\s+reported)[\s\S]{0,180}?"
        r"([A-Z][a-z]+\s+\d{1,2},?\s+\d{4}|\d{1,2}/\d{1,2}/\d{4}|\d{4}-\d{2}-\d{2})",
        text,
        flags=re.IGNORECASE,
    )
    return parse_date(match.group(1)) if match else None


def extract_10k_sections(text: str) -> tuple[str, str]:
    item1c = _longest_section(
        text,
        r"^\s*item\s+1c\b(?:\s*\.?\s*cybersecurity)?",
        r"^\s*item\s+(?:1d|2)\b",
    )
    item1a = _longest_section(
        text,
        r"^\s*item\s+1a\b(?:\s*\.?\s*(?:ris\s*k|risk)\s+factors)?",
        r"^\s*item\s+1b\b",
    )

    normalized = re.sub(r"\s+", " ", item1a).strip()
    sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z])", normalized) if normalized else []
    hit_indexes = {
        index
        for index, sentence in enumerate(sentences)
        if re.search(
            r"\b(cyber|ransomware|data breach|information security)\w*",
            sentence,
            re.IGNORECASE,
        )
    }
    context_indexes = sorted(
        index
        for hit in hit_indexes
        for index in (hit - 1, hit, hit + 1)
        if 0 <= index < len(sentences)
    )
    cyber_context = " ".join(sentences[index] for index in context_indexes)
    return item1c, cyber_context


def process_company(
    client: SecClient,
    company: dict[str, str],
    cutoff: date,
    *,
    latest_only: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cik = company["CIK"]
    audit: dict[str, Any] = {
        **company,
        "Status": "",
        "Item1.05_Filings_Found": 0,
        "Rows_Written": 0,
        "Error": "",
    }
    try:
        recent = fetch_filings(client, cik, cutoff)
        incidents = find_item105_filings(recent, cutoff)
        audit["Item1.05_Filings_Found"] = len(incidents)
        if not incidents:
            audit["Status"] = "no_item_1_05"
            return [], audit
        if latest_only:
            incidents = incidents[-1:]

        rows: list[dict[str, Any]] = []
        ten_k_cache: dict[str, tuple[str, str, str]] = {}
        for incident in incidents:
            eight_k_url = filing_url(cik, incident)
            eight_k_text = document_to_text(client.get_text(eight_k_url))
            item105_text = extract_item105_text(eight_k_text)
            reported_event_date = extract_reported_event_date(eight_k_text)
            disclosure_lag = (
                (incident["filingDate"] - reported_event_date).days
                if reported_event_date is not None
                else ""
            )

            ten_k = find_preceding_10k(recent, incident["filingDate"])
            ten_k_accession = ten_k["accessionNumber"] if ten_k else ""
            ten_k_date: date | str = ten_k["filingDate"] if ten_k else ""
            ten_k_url = filing_url(cik, ten_k) if ten_k else ""
            item1c = ""
            item1a_cyber = ""
            if ten_k:
                if ten_k_accession not in ten_k_cache:
                    ten_k_text = document_to_text(client.get_text(ten_k_url))
                    extracted_1c, extracted_1a = extract_10k_sections(ten_k_text)
                    ten_k_cache[ten_k_accession] = (
                        extracted_1c,
                        extracted_1a,
                        ten_k_url,
                    )
                item1c, item1a_cyber, ten_k_url = ten_k_cache[ten_k_accession]

            issues: list[str] = []
            if not item105_text:
                issues.append("item_1_05_text_not_found")
            if not ten_k:
                issues.append("no_preceding_10k")
            elif not item1c:
                issues.append("item_1c_not_found")
            if ten_k and not item1a_cyber:
                issues.append("item_1a_cyber_text_not_found")

            rows.append(
                {
                    **company,
                    "8K_Accession": incident["accessionNumber"],
                    "8K_Filing_Date": incident["filingDate"],
                    "8K_Reported_Event_Date": reported_event_date or "",
                    "Disclosure_Lag_Days": disclosure_lag,
                    "8K_URL": eight_k_url,
                    "8K_Item1.05_Text": item105_text,
                    "10K_Accession": ten_k_accession,
                    "10K_Filing_Date": ten_k_date,
                    "10K_URL": ten_k_url,
                    "10K_Item1C_Text": item1c,
                    "10K_Item1A_Cyber_Text": item1a_cyber,
                    "Extraction_Status": ";".join(issues) if issues else "complete",
                }
            )

        audit["Status"] = "processed"
        audit["Rows_Written"] = len(rows)
        return rows, audit
    except Exception as error:  # keep a batch moving while recording the failure
        audit["Status"] = "error"
        audit["Error"] = f"{type(error).__name__}: {error}"
        return [], audit


def existing_event_keys(path: Path) -> set[tuple[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return set()
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return {
            (row.get("CIK", ""), row.get("8K_Accession", ""))
            for row in csv.DictReader(handle)
        }


def write_rows(
    path: Path,
    rows: Iterable[dict[str, Any]],
    fieldnames: list[str],
    *,
    append: bool,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not append or not path.exists() or path.stat().st_size == 0
    with path.open("a" if append else "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        if needs_header:
            writer.writeheader()
        writer.writerows(rows)


def run_collection(args: argparse.Namespace) -> int:
    cutoff = parse_date(args.cutoff)
    if cutoff is None:
        raise ValueError(f"Invalid cutoff date: {args.cutoff}")

    if args.command == "single":
        companies = [
            {
                "CIK": format_cik(args.cik),
                "Ticker": args.ticker,
                "Company": args.company,
            }
        ]
    else:
        companies = load_company_universe(
            Path(args.input),
            cutoff,
            include_inactive=args.include_inactive,
            skip=args.skip,
            limit=args.limit,
        )

    output_path = Path(args.output)
    audit_path = Path(args.audit_output)
    resume = bool(args.resume)
    known_keys = existing_event_keys(output_path) if resume else set()
    if not resume:
        write_rows(output_path, [], INCIDENT_FIELDS, append=False)
        write_rows(audit_path, [], AUDIT_FIELDS, append=False)

    client = SecClient(args.user_agent, sleep_seconds=args.sleep)
    total_rows = 0
    for index, company in enumerate(companies, start=1):
        label = company["Ticker"] or company["CIK"]
        print(f"[{index}/{len(companies)}] {label}")
        rows, audit = process_company(
            client,
            company,
            cutoff,
            latest_only=args.latest_only,
        )
        new_rows = [
            row
            for row in rows
            if (str(row["CIK"]), str(row["8K_Accession"])) not in known_keys
        ]
        for row in new_rows:
            known_keys.add((str(row["CIK"]), str(row["8K_Accession"])))
        audit["Rows_Written"] = len(new_rows)
        write_rows(output_path, new_rows, INCIDENT_FIELDS, append=True)
        write_rows(audit_path, [audit], AUDIT_FIELDS, append=True)
        total_rows += len(new_rows)

    print(f"Processed {len(companies)} companies; wrote {total_rows} incident rows.")
    print(f"Incidents: {output_path}")
    print(f"Audit: {audit_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--user-agent",
        default=os.getenv("SEC_USER_AGENT", ""),
        help="Descriptive identity/contact string; may also be set with SEC_USER_AGENT.",
    )
    parser.add_argument("--sleep", type=float, default=DEFAULT_SLEEP_SECONDS)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_shared(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument("--cutoff", default=DEFAULT_CUTOFF.isoformat())
        subparser.add_argument("--output", default="outputs/incidents.csv")
        subparser.add_argument("--audit-output", default="outputs/company_audit.csv")
        subparser.add_argument("--latest-only", action="store_true")
        subparser.add_argument("--resume", action="store_true")

    single = subparsers.add_parser("single", help="Validate one company.")
    add_shared(single)
    single.add_argument("--cik", required=True)
    single.add_argument("--ticker", default="")
    single.add_argument("--company", default="")

    batch = subparsers.add_parser("batch", help="Process a CSV company universe.")
    add_shared(batch)
    batch.add_argument("--input", required=True)
    batch.add_argument("--skip", type=int, default=0)
    batch.add_argument("--limit", type=int)
    batch.add_argument("--include-inactive", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not args.user_agent.strip():
        parser.error("set --user-agent or the SEC_USER_AGENT environment variable")
    return run_collection(args)


if __name__ == "__main__":
    raise SystemExit(main())
