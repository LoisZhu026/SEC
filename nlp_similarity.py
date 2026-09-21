"""Score the textual gap between a pre-event 10-K and an Item 1.05 8-K."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


def preprocess(text: object) -> str:
    if not isinstance(text, str) or not text.strip():
        return ""
    normalized = re.sub(r"[^a-z\s]", " ", text.lower())
    return " ".join(
        token
        for token in normalized.split()
        if len(token) > 1 and token not in ENGLISH_STOP_WORDS
    )


def compute_similarity(text_a: str, text_b: str) -> tuple[float | None, float | None]:
    if not text_a or not text_b:
        return None, None
    try:
        matrix = TfidfVectorizer().fit_transform([text_a, text_b])
    except ValueError:
        return None, None
    similarity = float(cosine_similarity(matrix[0], matrix[1])[0][0])
    return round(similarity, 6), round(1.0 - similarity, 6)


def score_dataframe(frame: pd.DataFrame) -> pd.DataFrame:
    incident_column = "8K_Item1.05_Text"
    item1a_column = (
        "10K_Item1A_Cyber_Text"
        if "10K_Item1A_Cyber_Text" in frame.columns
        else "10K_Item1A_Text"
    )
    required = {incident_column, "10K_Item1C_Text", item1a_column}
    missing = sorted(required.difference(frame.columns))
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")

    scored = frame.copy()
    scored["Pre_Event_10K_Text"] = (
        scored["10K_Item1C_Text"].fillna("").astype(str)
        + " "
        + scored[item1a_column].fillna("").astype(str)
    ).str.strip()

    similarities: list[float | None] = []
    gaps: list[float | None] = []
    for pre_event, incident in zip(
        scored["Pre_Event_10K_Text"], scored[incident_column], strict=False
    ):
        similarity, gap = compute_similarity(preprocess(pre_event), preprocess(incident))
        similarities.append(similarity)
        gaps.append(gap)
    scored["Cosine_Similarity"] = similarities
    scored["Textual_Gap"] = gaps
    return scored


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Incident CSV from sec_poc.py.")
    parser.add_argument("--output", required=True, help="Destination scored CSV.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    frame = pd.read_csv(input_path, encoding="utf-8-sig")
    scored = score_dataframe(frame)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    scored.to_csv(output_path, index=False, encoding="utf-8-sig")
    completed = int(scored["Cosine_Similarity"].notna().sum())
    print(f"Scored {completed}/{len(scored)} rows: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
