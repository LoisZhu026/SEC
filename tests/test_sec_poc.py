import csv
import tempfile
import unittest
from datetime import date
from pathlib import Path

from sec_poc import (
    extract_10k_sections,
    extract_item105_text,
    extract_reported_event_date,
    find_item105_filings,
    find_preceding_10k,
    format_cik,
    load_company_universe,
)


class SecPipelineTests(unittest.TestCase):
    def test_format_cik_accepts_numeric_and_excel_values(self):
        self.assertEqual(format_cik("789019"), "0000789019")
        self.assertEqual(format_cik("789019.0"), "0000789019")
        with self.assertRaises(ValueError):
            format_cik("MSFT")

    def test_company_universe_filters_then_deduplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "companies.csv"
            with path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["cik", "tic", "conm", "timeLinkEnd_d"],
                )
                writer.writeheader()
                writer.writerows(
                    [
                        {
                            "cik": "789019.0",
                            "tic": "MSFT",
                            "conm": "Microsoft",
                            "timeLinkEnd_d": "",
                        },
                        {
                            "cik": "789019",
                            "tic": "OLD",
                            "conm": "Duplicate",
                            "timeLinkEnd_d": "",
                        },
                        {
                            "cik": "320193",
                            "tic": "AAPL",
                            "conm": "Apple",
                            "timeLinkEnd_d": "2020-01-01",
                        },
                        {
                            "cik": "1652044",
                            "tic": "GOOGL",
                            "conm": "Alphabet",
                            "timeLinkEnd_d": "",
                        },
                    ]
                )
            companies = load_company_universe(
                path, date(2023, 12, 18), skip=1, limit=1
            )
            self.assertEqual(companies, [{"CIK": "0001652044", "Ticker": "GOOGL", "Company": "Alphabet"}])

    def test_filing_selection_and_preceding_10k(self):
        recent = {
            "form": ["8-K", "8-K", "10-K", "10-K"],
            "filingDate": ["2024-01-02", "2023-11-01", "2023-08-01", "2022-08-01"],
            "accessionNumber": ["a", "b", "c", "d"],
            "primaryDocument": ["a.htm", "b.htm", "c.htm", "d.htm"],
            "items": ["1.05,9.01", "1.05", "", ""],
        }
        incidents = find_item105_filings(recent, date(2023, 12, 18))
        self.assertEqual([item["accessionNumber"] for item in incidents], ["a"])
        preceding = find_preceding_10k(recent, date(2024, 1, 2))
        self.assertEqual(preceding["accessionNumber"], "c")

    def test_extracts_long_body_sections_and_reported_date(self):
        eight_k = """
        Date of Report (Date of earliest event reported) January 2, 2024
        Item 1.05 Material Cybersecurity Incidents short contents
        Item 9.01
        Item 1.05 Material Cybersecurity Incidents
        The company identified unauthorized access to systems and began containment.
        Additional investigation remains ongoing.
        Item 9.01 Financial Statements and Exhibits
        """
        extracted = extract_item105_text(eight_k)
        self.assertIn("unauthorized access", extracted)
        self.assertEqual(extract_reported_event_date(eight_k), date(2024, 1, 2))

        ten_k = """
        Item 1A Risk Factors contents only Item 1B
        Item 1C Cybersecurity contents only Item 2
        Item 1A Risk Factors
        General business risks may affect us. A cybersecurity attack could interrupt operations.
        We maintain controls, but a data breach may still occur. Other market risks also apply.
        Item 1B Unresolved Staff Comments
        Item 1C Cybersecurity
        Management assesses material cybersecurity risks through a documented program.
        The board receives regular reporting about information security.
        Item 2 Properties
        """
        item1c, item1a_cyber = extract_10k_sections(ten_k)
        self.assertIn("documented program", item1c)
        self.assertIn("cybersecurity attack", item1a_cyber)


if __name__ == "__main__":
    unittest.main()
