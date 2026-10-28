"""
Score Combiner
---------------
Merges the three layers (rule engine, link analyzer, ML model) into one
final verdict.

EVIDENCE-ADDING design: each layer ADDS points when it sees something
suspicious. Layers never dilute each other. (An earlier version averaged
them, which meant that when the rules missed a scam, the ML layer alone
could never push the message above the 'Suspicious' threshold.)

    final = rule_score*1.0 + link_score*0.8 + ml_score*0.3   (capped at 100)

    final >= 60  -> Dangerous
    final >= 30  -> Suspicious
    otherwise    -> Safe
"""

from rule_engine import evaluate as rule_evaluate
from link_analyzer import analyze as link_analyze
from ml_predictor import predict_score as ml_predict_score

# How many points each layer can contribute. Tune with real test data.
WEIGHTS = {
    "rule": 1.0,
    "link": 0.8,
    "ml": 0.3,
}

DANGEROUS_AT = 60
SUSPICIOUS_AT = 30


def classify(final_score: float) -> str:
    if final_score >= DANGEROUS_AT:
        return "Dangerous"
    if final_score >= SUSPICIOUS_AT:
        return "Suspicious"
    return "Safe"


def get_verdict(raw_text: str, ml_score: float = None) -> dict:
    rule_result = rule_evaluate(raw_text)
    link_result = link_analyze(rule_result["normalized_text"])

    # If no ml_score was passed in explicitly, get one from the trained model
    # (returns 0 automatically if the model isn't available).
    if ml_score is None:
        ml_score = ml_predict_score(raw_text)

    final_score = (
        rule_result["rule_score"] * WEIGHTS["rule"]
        + link_result["link_score"] * WEIGHTS["link"]
        + ml_score * WEIGHTS["ml"]
    )
    final_score = round(min(final_score, 100), 1)

    reasons = list(rule_result["reasons"])
    for finding in link_result["findings"]:
        reasons.extend(f"{finding['domain']}: {flag}" for flag in finding["flags"])
    if ml_score >= 60:
        reasons.append("The trained model found this message similar to known phishing messages")

    return {
        "message": raw_text,
        "script": rule_result["script"],
        "final_score": final_score,
        "verdict": classify(final_score),
        "reasons": reasons,
        "links": link_result["findings"],
        "weights": WEIGHTS,
        "sub_scores": {
            "rule_score": rule_result["rule_score"],
            "link_score": link_result["link_score"],
            "ml_score": ml_score,
        },
    }


if __name__ == "__main__":
    tests = [
        "ሰላም! ሂሳብዎ ይታገዳል!!! አሁኑኑ የይለፍ ቃልዎን ያስገቡ http://telebirr-verify.com",
        "Hi, are we still meeting tomorrow at 5?",
        "congratulation you win 100 dollar",
    ]
    for t in tests:
        v = get_verdict(t)
        print(f"\nMessage: {t}")
        print(f"Verdict: {v['verdict']} (score {v['final_score']})")
        print("Reasons:", v["reasons"])
