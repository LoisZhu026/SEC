"""
NLP Textual Gap Analysis — Single Sample Validation (MSFT PoC)
输入: SEC_Cybersecurity_Data_PoC.csv
输出: SEC_Cybersecurity_Data_PoC_Scored.csv

核心指标:
  Cosine_Similarity  = TF-IDF 余弦相似度 (0~1, 越高越相似)
  Textual_Gap        = 1 - Cosine_Similarity (越高代表事前披露与事后实锤差距越大)
"""

import re
import os
import pandas as pd
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# ─────────────────────────────────────────────
# 路径配置
# ─────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
INPUT_CSV   = os.path.join(BASE_DIR, "SEC_Cybersecurity_Data_PoC.csv")
OUTPUT_CSV  = os.path.join(BASE_DIR, "SEC_Cybersecurity_Data_PoC_Scored.csv")

# ─────────────────────────────────────────────
# Step 0: 加载停用词表
# ─────────────────────────────────────────────
STOP_WORDS = set(stopwords.words("english"))


# ─────────────────────────────────────────────
# Step 1 辅助函数: 文本预处理
# ─────────────────────────────────────────────
def preprocess(text: str) -> str:
    """
    标准 NLP 预处理:
      1. 转小写
      2. 去除标点和特殊字符（保留字母和空格）
      3. 去除停用词
    如果输入为空/NaN，返回空字符串。
    """
    # 处理空值
    if not isinstance(text, str) or text.strip() == "":
        return ""

    # 1. 转小写
    text = text.lower()

    # 2. 去除标点和特殊字符（只保留 a-z 和空格）
    text = re.sub(r"[^a-z\s]", " ", text)

    # 3. 分词 + 去停用词
    tokens = [w for w in text.split() if w not in STOP_WORDS and len(w) > 1]

    return " ".join(tokens)


# ─────────────────────────────────────────────
# Step 2: 计算单对文本的 TF-IDF 余弦相似度
# ─────────────────────────────────────────────
def compute_similarity(text_a: str, text_b: str) -> tuple[float, float]:
    """
    对两段预处理后的文本计算 TF-IDF 余弦相似度。
    返回 (cosine_similarity, textual_gap)。
    如果任意一段为空，返回 (None, None)。
    """
    if not text_a or not text_b:
        return None, None

    # TfidfVectorizer 同时对两段文本建立词汇表并向量化
    vectorizer = TfidfVectorizer()
    tfidf_matrix = vectorizer.fit_transform([text_a, text_b])

    # tfidf_matrix[0] = text_a 的向量, tfidf_matrix[1] = text_b 的向量
    cos_sim = cosine_similarity(tfidf_matrix[0], tfidf_matrix[1])[0][0]
    textual_gap = 1.0 - cos_sim

    return round(float(cos_sim), 6), round(float(textual_gap), 6)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print("=" * 60)
    print("NLP Textual Gap Analysis — PoC (MSFT)")
    print("=" * 60)

    # ── 读取 CSV ──
    if not os.path.exists(INPUT_CSV):
        raise FileNotFoundError(f"Input file not found: {INPUT_CSV}")

    df = pd.read_csv(INPUT_CSV, encoding="utf-8-sig")
    print(f"\n[Load] {len(df)} row(s) loaded from {INPUT_CSV}")
    print(f"       Columns: {list(df.columns)}\n")

    # ── Step 1: 拼接 10-K 文本，构建 Pre_Event_10K_Text ──
    # 用空格拼接 Item 1C 和 Item 1A，NaN 视为空字符串
    df["Pre_Event_10K_Text"] = (
        df["10K_Item1C_Text"].fillna("") + " " + df["10K_Item1A_Text"].fillna("")
    ).str.strip()

    print("[Step 1] Pre_Event_10K_Text constructed.")
    print(f"  Length (chars): {df['Pre_Event_10K_Text'].str.len().iloc[0]}")

    # ── Step 2: 文本预处理 ──
    df["_pre_event_clean"] = df["Pre_Event_10K_Text"].apply(preprocess)
    df["_8k_clean"]        = df["8K_Item1.05_Text"].apply(preprocess)

    print("\n[Step 2] Text preprocessing done.")
    print(f"  Pre-event tokens : {len(df['_pre_event_clean'].iloc[0].split())}")
    print(f"  8-K tokens       : {len(df['_8k_clean'].iloc[0].split())}")

    # ── Step 3: TF-IDF 余弦相似度 ──
    results = []
    for idx, row in df.iterrows():
        cos_sim, gap = compute_similarity(
            row["_pre_event_clean"],
            row["_8k_clean"]
        )
        results.append({"Cosine_Similarity": cos_sim, "Textual_Gap": gap})

        # 打印结果
        ticker = row.get("Ticker", f"row_{idx}")
        if cos_sim is not None:
            print(f"\n[Step 3] {ticker}")
            print(f"  Cosine Similarity : {cos_sim:.6f}")
            print(f"  Textual Gap       : {gap:.6f}")
            # 简单解读
            if gap > 0.85:
                label = "⚠ HIGH GAP — 事前披露与事后实锤差距显著（典型套话）"
            elif gap > 0.60:
                label = "△ MODERATE GAP — 有一定预警但不充分"
            else:
                label = "✓ LOW GAP — 事前披露与事后描述较为一致"
            print(f"  Interpretation    : {label}")
        else:
            print(f"\n[Step 3] {ticker} — SKIPPED (one or both texts are empty)")

    # ── Step 4: 写回 DataFrame 并导出 ──
    results_df = pd.DataFrame(results, index=df.index)
    df = pd.concat([df, results_df], axis=1)

    # 删除临时预处理列（不需要存入 CSV）
    df.drop(columns=["_pre_event_clean", "_8k_clean"], inplace=True)

    df.to_csv(OUTPUT_CSV, index=False, encoding="utf-8-sig")
    print(f"\n[Output] Scored CSV saved to:")
    print(f"  {OUTPUT_CSV}")
    print("=" * 60)


if __name__ == "__main__":
    main()
