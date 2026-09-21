# Microsoft validation files

The three files beginning with `SEC_Cybersecurity_Data_PoC` are the original one-filing proof of concept that existed before this repository was reorganized. They are retained as a record of the initial work.

The files beginning with `current_` were regenerated with the current pipeline on 21 September 2026:

- `current_incidents.csv` contains the 19 January 2024 Item 1.05 disclosure and the 8 March 2024 amendment;
- `current_incidents_scored.csv` adds cosine similarity and textual-gap scores for both filings;
- `current_company_audit.csv` records that Microsoft was processed and two rows were written.

Both current rows report `item_1c_not_found`. This is expected because the matched preceding 10-K was filed on 27 July 2023, before the SEC's Item 1C requirement applied to that annual report. The cybersecurity context from Item 1A was extracted and used for scoring.
