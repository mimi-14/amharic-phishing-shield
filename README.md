# Amharic Phishing Shield — Starter Code

Phase 1–3 implementation (text normalization, rule engine, link analyzer, combined scoring, basic API).

## Setup

```bash
python3 -m venv venv
source venv/bin/activate      # on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run the demo

```bash
cd app
uvicorn main:app --reload
```

Then open:
- `http://127.0.0.1:8000/` — simple demo page (paste a message, get a verdict)
- `http://127.0.0.1:8000/docs` — interactive API tester (Swagger UI)

## Project structure

```
amharic-phishing-shield/
├── app/
│   ├── normalizer.py     # Amharic text normalization (Phase 2)
│   ├── rule_engine.py     # Rule-based detection (Phase 2)
│   ├── link_analyzer.py   # URL / domain / certificate checks (Phase 3)
│   ├── scoring.py          # Combines all scores into a final verdict
│   └── main.py             # FastAPI app + demo page
├── data/                   # Put your labeled dataset CSV here (Phase 1/4)
├── models/                 # Trained ML model files go here (Phase 4)
├── tests/                  # Add unit tests here
└── requirements.txt
```

## What's already working

- ✅ Amharic character normalization (handles homoglyphs like ሀ/ሃ/ሐ)
- ✅ Transliterated Amharic detection ("yitagedal" → ይታገዳል)
- ✅ Script detection (Amharic / English / mixed)
- ✅ Rule-based scoring (urgency, prize bait, credential requests, brand impersonation)
- ✅ URL extraction, shortener detection, lookalike domain detection
- ✅ Certificate check (fails gracefully offline)
- ✅ Combined scoring → Safe / Suspicious / Dangerous verdict
- ✅ Working API + demo web page

## What's next (per the phased plan)

- **Phase 1 (parallel):** Build out the labeled dataset in `data/` (200–500 messages)
- **Phase 4:** Train the ML classifier (`scikit-learn` TF-IDF + Logistic Regression baseline)
  wire its output into `scoring.py`'s `ml_score` parameter
- **Phase 5:** Polish the UI (or swap in a nicer frontend), optionally add the Telegram bot
- **Phase 6:** Test against a wide range of real-style messages, tune the `WEIGHTS` in `scoring.py`

## Known limitation to fix

`link_analyzer.py`'s URL regex only matches domains ending in `.com/.net/.org/.et` —
extend `URL_PATTERN` to catch other shortener domains like `bit.ly` (`.ly` TLD) properly.

## Extending the rule engine

Add new phrases to the pattern lists in `rule_engine.py` (`URGENCY_PATTERNS`,
`MONEY_PRIZE_PATTERNS`, etc.) as you discover more real scam wording — this is
the fastest way to improve accuracy before the ML model is trained.
