"""
FastAPI entry point + demo interface.

Run (from the app/ folder):
    uvicorn main:app --reload

Then open:
    http://127.0.0.1:8000/        the demo interface
    http://127.0.0.1:8000/docs    interactive API tester

To let a phone on the same Wi-Fi try it, run instead:
    uvicorn main:app --host 0.0.0.0 --port 8000
and open http://<your-computer-ip>:8000 on the phone.
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from scoring import get_verdict

app = FastAPI(title="Amharic Phishing Shield")


class MessageIn(BaseModel):
    text: str = Field(..., max_length=2000)


@app.post("/analyze")
def analyze_message(payload: MessageIn):
    return get_verdict(payload.text)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def demo_page():
    return PAGE


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Amharic Phishing Shield</title>
<style>
:root{
  --bg:#f5f6fa; --card:#ffffff; --text:#14171f; --muted:#5b6475; --border:#e1e5ee;
  --accent:#1d4ed8; --accent-text:#ffffff; --track:#e8ebf2;
  --safe:#15803d; --safe-bg:#e7f5ec;
  --warn:#a15c07; --warn-bg:#fcf1dc;
  --danger:#b91c1c; --danger-bg:#fce9e9;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#0e1117; --card:#161a23; --text:#eceff6; --muted:#9ba5ba; --border:#262c3a;
    --accent:#6ea0ff; --accent-text:#0b1020; --track:#262c3a;
    --safe:#4ade80; --safe-bg:#12301f;
    --warn:#fbbf24; --warn-bg:#392a0d;
    --danger:#f87171; --danger-bg:#3a1616;
  }
}
*{box-sizing:border-box}
body{
  margin:0; background:var(--bg); color:var(--text); line-height:1.5;
  font-family:"Segoe UI","Ebrima","Nyala","Noto Sans Ethiopic",system-ui,-apple-system,Roboto,sans-serif;
}
.wrap{max-width:780px; margin:0 auto; padding:28px 18px 56px}
header{display:flex; align-items:center; gap:14px; margin-bottom:6px}
.logo{font-size:38px; line-height:1}
h1{font-size:1.5rem; margin:0}
.sub{margin:2px 0 0; color:var(--muted); font-size:.95rem}
.card{
  background:var(--card); border:1px solid var(--border); border-radius:14px;
  padding:18px; margin-top:18px;
}
label.title{display:block; font-weight:600; margin-bottom:8px}
textarea{
  width:100%; min-height:120px; resize:vertical; padding:12px; font:inherit; font-size:1rem;
  color:var(--text); background:var(--bg); border:1px solid var(--border); border-radius:10px;
}
textarea:focus, button:focus-visible{outline:3px solid var(--accent); outline-offset:2px}
.row{display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-top:12px}
button{font:inherit; cursor:pointer; border-radius:10px}
.primary{
  background:var(--accent); color:var(--accent-text); border:0; padding:10px 22px; font-weight:600;
}
.primary:disabled{opacity:.6; cursor:progress}
.ghost{background:transparent; color:var(--muted); border:1px solid var(--border); padding:9px 16px}
.hint{color:var(--muted); font-size:.85rem; margin-left:auto}
.chips-label{margin:16px 0 6px; font-size:.85rem; color:var(--muted)}
.chips{display:flex; flex-wrap:wrap; gap:8px}
.chip{
  background:var(--card); color:var(--text); border:1px solid var(--border);
  padding:6px 12px; font-size:.88rem; border-radius:999px;
}
.chip:hover{border-color:var(--accent)}
.chip.bad::before{content:"\26A0\FE0F  "}
.chip.good::before{content:"\2713  "}

.result{display:none}
.result.show{display:block}
.verdict{
  display:flex; align-items:center; gap:14px; padding:14px 16px; border-radius:12px;
}
.verdict .icon{
  width:46px; height:46px; border-radius:50%; display:grid; place-items:center;
  font-size:24px; font-weight:700; color:#fff; flex:none;
}
.verdict .label{font-size:1.35rem; font-weight:700; line-height:1.2}
.verdict .label small{display:block; font-size:.95rem; font-weight:600; opacity:.85}
.safe .verdict{background:var(--safe-bg); color:var(--safe)}
.safe .icon, .safe .fill{background:var(--safe)}
.warn .verdict{background:var(--warn-bg); color:var(--warn)}
.warn .icon, .warn .fill{background:var(--warn)}
.danger .verdict{background:var(--danger-bg); color:var(--danger)}
.danger .icon, .danger .fill{background:var(--danger)}
.score{margin-left:auto; text-align:right; font-weight:700; font-size:1.6rem; line-height:1}
.score small{display:block; font-size:.75rem; font-weight:500; opacity:.8; margin-top:4px}

.meter{position:relative; margin:18px 4px 6px; height:12px; border-radius:6px; overflow:visible;
  background:linear-gradient(90deg,
    var(--safe-bg) 0 30%, var(--warn-bg) 30% 60%, var(--danger-bg) 60% 100%);
  border:1px solid var(--border)}
.needle{position:absolute; top:-6px; width:4px; height:24px; border-radius:2px;
  background:var(--text); transform:translateX(-50%); transition:left .5s ease}
.zones{display:flex; margin:6px 4px 0; font-size:.75rem; color:var(--muted)}
.zones span:nth-child(1){width:30%} .zones span:nth-child(2){width:30%} .zones span:nth-child(3){flex:1; text-align:right}

.advice{margin:16px 0 0; font-size:1rem}
.advice .am{display:block; margin-top:4px; color:var(--muted)}
h2{font-size:1rem; margin:22px 0 8px}
ul.reasons{margin:0; padding-left:20px}
ul.reasons li{margin:4px 0}
.none{color:var(--muted); margin:0}
.layer{display:grid; grid-template-columns:90px 1fr 70px; gap:10px; align-items:center; margin:8px 0}
.layer .name{font-weight:600; font-size:.92rem}
.layer .bar{height:10px; border-radius:5px; background:var(--track); overflow:hidden}
.layer .fill{height:100%; border-radius:5px; width:0; transition:width .5s ease}
.layer .pts{text-align:right; font-size:.88rem; color:var(--muted)}
.layer .desc{grid-column:2 / 4; font-size:.8rem; color:var(--muted); margin-top:-4px}
.formula{font-size:.8rem; color:var(--muted); margin:8px 0 0}
.link{padding:8px 10px; border:1px solid var(--border); border-radius:8px; margin:6px 0;
  font-size:.9rem}
.link code{font-family:Consolas,"Courier New",monospace; word-break:break-all}
.link ul{margin:4px 0 0; padding-left:18px; color:var(--muted)}
.badge{display:inline-block; font-size:.78rem; padding:2px 9px; border-radius:999px;
  border:1px solid var(--border); color:var(--muted); margin-left:8px; vertical-align:middle}
.error{background:var(--danger-bg); color:var(--danger); padding:12px 14px; border-radius:10px}
footer{margin-top:22px; font-size:.8rem; color:var(--muted); text-align:center}
@media (max-width:520px){
  .verdict{flex-wrap:wrap}
  .layer{grid-template-columns:70px 1fr 60px}
  .hint{display:none}
}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="logo" aria-hidden="true">&#128737;&#65039;</div>
    <div>
      <h1>Amharic Phishing Shield <span class="badge">አማርኛ ፊሺንግ ጋሻ</span></h1>
      <p class="sub">Paste a suspicious SMS, Telegram or email message. Works in Amharic, English, or a mix of both.</p>
    </div>
  </header>

  <section class="card">
    <label class="title" for="msg">Message to check</label>
    <textarea id="msg" maxlength="2000"
      placeholder="Paste a suspicious message here...&#10;የተጠራጠሩትን መልእክት እዚህ ይለጥፉ"></textarea>
    <div class="row">
      <button class="primary" id="go" type="button">Analyze</button>
      <button class="ghost" id="clear" type="button">Clear</button>
      <span class="hint">Ctrl + Enter to analyze</span>
    </div>
    <div class="chips-label">Try an example:</div>
    <div class="chips" id="chips"></div>
  </section>

  <section class="card result" id="result" aria-live="polite"></section>

  <footer>
    A detection aid, not a guarantee. When in doubt, contact your bank or telecom on its official number.
    Messages are not saved.
  </footer>
</div>

<script>
(function () {
  "use strict";

  var EXAMPLES = [
    {label: "Amharic scam", bad: true,
     text: "ውድ ደንበኛ፣ የቴሌብር ሂሳብዎ ታግዷል። ፒን ኮድዎን ይላኩ http://telebirr-verify.com"},
    {label: "Prize scam", bad: true,
     text: "Congratulations! You've won 50000 birr, claim now: bit.ly/xyz123"},
    {label: "Mixed-script scam", bad: true,
     text: "Selam, account'wo yitagedal, ahunu click yaregu http://ethiotelecom-bonus.com"},
    {label: "Normal message", bad: false, text: "Hi, are we still meeting tomorrow at 5?"},
    {label: "Normal Amharic", bad: false, text: "ነገ ማታ ለእራት ቤታችን ኑ"}
  ];

  var VERDICTS = {
    "Safe": {
      cls: "safe", icon: "\u2713", en: "Looks safe", am: "ደህንነቱ የተጠበቀ",
      adviceEn: "No clear scam signals were found. Still be careful with links and with requests for money or codes.",
      adviceAm: "ግልጽ የማጭበርበር ምልክት አልተገኘም። ስለ ሊንኮች እና ገንዘብ ወይም ኮድ ጥያቄዎች ጥንቃቄ ያድርጉ።"
    },
    "Suspicious": {
      cls: "warn", icon: "!", en: "Be careful", am: "አጠራጣሪ",
      adviceEn: "This message has some scam signals. Do not click links or share codes. Confirm with the sender through another channel.",
      adviceAm: "ይህ መልእክት አንዳንድ የማጭበርበር ምልክቶች አሉት። ሊንኮችን አይጫኑ፣ ኮድ አይላኩ። ላኪውን በሌላ መንገድ ያረጋግጡ።"
    },
    "Dangerous": {
      cls: "danger", icon: "\u2715", en: "Very likely a scam", am: "አደገኛ",
      adviceEn: "Do not click any link or send any PIN, password or code. Delete the message.",
      adviceAm: "ማንኛውንም ሊንክ አይጫኑ፣ ፒን፣ የይለፍ ቃል ወይም ኮድ አይላኩ። መልእክቱን ይሰርዙ።"
    }
  };

  var SCRIPTS = {am: "Amharic", en: "English", mixed: "Amharic + English", unknown: "Unknown"};

  var LAYERS = [
    {key: "rule_score", w: "rule", name: "Rules",
     desc: "Scam wording: urgency, prizes, requests for PINs and codes"},
    {key: "link_score", w: "link", name: "Links",
     desc: "Lookalike domains, shortened links, certificates"},
    {key: "ml_score", w: "ml", name: "ML model",
     desc: "How similar the message is to known phishing messages"}
  ];

  function $(id) { return document.getElementById(id); }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (text !== undefined) { n.textContent = text; }   // textContent: never interprets HTML
    return n;
  }

  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }

  function round1(x) { return Math.round(x * 10) / 10; }

  function render(d) {
    var v = VERDICTS[d.verdict] || VERDICTS["Safe"];
    var box = $("result");
    clear(box);
    box.className = "card result show " + v.cls;

    // verdict banner
    var banner = el("div", "verdict");
    banner.appendChild(el("div", "icon", v.icon));
    var label = el("div", "label", v.en);
    label.appendChild(el("small", "", v.am + " \u00b7 " + d.verdict));
    banner.appendChild(label);
    var score = el("div", "score", String(Math.round(d.final_score)));
    score.appendChild(el("small", "", "risk score / 100"));
    banner.appendChild(score);
    box.appendChild(banner);

    // meter with zones and needle
    var meter = el("div", "meter");
    meter.setAttribute("role", "img");
    meter.setAttribute("aria-label", "Risk score " + Math.round(d.final_score) + " out of 100");
    var needle = el("div", "needle");
    needle.style.left = Math.max(0, Math.min(100, d.final_score)) + "%";
    meter.appendChild(needle);
    box.appendChild(meter);
    var zones = el("div", "zones");
    zones.appendChild(el("span", "", "Safe"));
    zones.appendChild(el("span", "", "Suspicious"));
    zones.appendChild(el("span", "", "Dangerous"));
    box.appendChild(zones);

    // advice (English + Amharic)
    var advice = el("p", "advice", v.adviceEn);
    advice.appendChild(el("span", "am", v.adviceAm));
    box.appendChild(advice);

    // reasons
    var h = el("h2", "", "Why this verdict");
    h.appendChild(el("span", "badge", "Detected: " + (SCRIPTS[d.script] || SCRIPTS.unknown)));
    box.appendChild(h);
    if (d.reasons && d.reasons.length) {
      var ul = el("ul", "reasons");
      d.reasons.forEach(function (r) { ul.appendChild(el("li", "", r)); });
      box.appendChild(ul);
    } else {
      box.appendChild(el("p", "none", "No suspicious signals were found."));
    }

    // layer contributions
    box.appendChild(el("h2", "", "How each layer voted"));
    var weights = d.weights || {rule: 1, link: 0.8, ml: 0.3};
    LAYERS.forEach(function (L) {
      var raw = (d.sub_scores && d.sub_scores[L.key]) || 0;
      var pts = round1(raw * (weights[L.w] || 0));
      var row = el("div", "layer");
      row.title = "Layer score " + raw + " / 100, weight " + (weights[L.w] || 0);
      row.appendChild(el("div", "name", L.name));
      var bar = el("div", "bar");
      var fill = el("div", "fill");
      fill.style.width = Math.max(0, Math.min(100, pts)) + "%";
      bar.appendChild(fill);
      row.appendChild(bar);
      row.appendChild(el("div", "pts", "+" + pts + " pts"));
      row.appendChild(el("div", "desc", L.desc));
      box.appendChild(row);
    });
    box.appendChild(el("p", "formula",
      "Final score = Rules \u00d7 " + (weights.rule || 0) + " + Links \u00d7 " + (weights.link || 0) +
      " + ML \u00d7 " + (weights.ml || 0) + " (max 100). Suspicious from 30, Dangerous from 60."));

    // links found
    if (d.links && d.links.length) {
      box.appendChild(el("h2", "", "Links found"));
      d.links.forEach(function (lk) {
        var item = el("div", "link");
        item.appendChild(el("code", "", lk.url));
        if (lk.flags && lk.flags.length) {
          var fl = el("ul");
          lk.flags.forEach(function (f) { fl.appendChild(el("li", "", f)); });
          item.appendChild(fl);
        }
        box.appendChild(item);
      });
    }
  }

  function showError(msg) {
    var box = $("result");
    clear(box);
    box.className = "card result show";
    box.appendChild(el("div", "error", msg));
  }

  var busy = false;

  function analyze() {
    var text = $("msg").value.trim();
    if (!text) { showError("Please paste a message first. / መጀመሪያ መልእክት ይለጥፉ።"); return; }
    if (busy) { return; }
    busy = true;
    var btn = $("go");
    btn.disabled = true;
    btn.textContent = "Analyzing\u2026";

    fetch("/analyze", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({text: text})
    })
      .then(function (r) {
        if (!r.ok) { throw new Error("Server answered " + r.status); }
        return r.json();
      })
      .then(render)
      .catch(function (e) {
        showError("Could not reach the analyzer (" + e.message + "). Is the server still running?");
      })
      .then(function () {
        busy = false;
        btn.disabled = false;
        btn.textContent = "Analyze";
      });
  }

  // example chips: fill the box and analyze in one click
  var chips = $("chips");
  EXAMPLES.forEach(function (ex) {
    var b = el("button", "chip " + (ex.bad ? "bad" : "good"), ex.label);
    b.type = "button";
    b.addEventListener("click", function () { $("msg").value = ex.text; analyze(); });
    chips.appendChild(b);
  });

  $("go").addEventListener("click", analyze);
  $("clear").addEventListener("click", function () {
    $("msg").value = "";
    clear($("result"));
    $("result").className = "card result";
    $("msg").focus();
  });
  $("msg").addEventListener("keydown", function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { analyze(); }
  });
})();
</script>
</body>
</html>
"""
