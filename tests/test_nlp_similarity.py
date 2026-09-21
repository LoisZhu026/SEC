import unittest

import pandas as pd

from nlp_similarity import compute_similarity, preprocess, score_dataframe


class NlpSimilarityTests(unittest.TestCase):
    def test_similarity_bounds_and_empty_input(self):
        cleaned = preprocess("Cybersecurity controls protect the network.")
        similarity, gap = compute_similarity(cleaned, cleaned)
        self.assertEqual(similarity, 1.0)
        self.assertEqual(gap, 0.0)
        self.assertEqual(compute_similarity("", cleaned), (None, None))

    def test_scores_current_output_schema(self):
        source = pd.DataFrame(
            [
                {
                    "8K_Item1.05_Text": "A ransomware incident affected systems.",
                    "10K_Item1C_Text": "We manage cybersecurity risk.",
                    "10K_Item1A_Cyber_Text": "A cyberattack may affect systems.",
                }
            ]
        )
        scored = score_dataframe(source)
        self.assertIn("Cosine_Similarity", scored.columns)
        self.assertGreaterEqual(scored.loc[0, "Textual_Gap"], 0.0)
        self.assertLessEqual(scored.loc[0, "Textual_Gap"], 1.0)


if __name__ == "__main__":
    unittest.main()
