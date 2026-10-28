"""
Generates a labeled starter dataset of phishing and legitimate messages
in Amharic, English, and mixed script, for training the Phase 4 ML model.

Run: python3 generate_dataset.py
Output: labeled_messages.csv (columns: text, label, language)
"""

import csv
import random

random.seed(42)

# ---------------------------------------------------------------------
# PHISHING MESSAGE TEMPLATES
# ---------------------------------------------------------------------

phishing_amharic = [
    "ሰላም! ሂሳብዎ ይታገዳል!!! አሁኑኑ የይለፍ ቃልዎን ያስገቡ {link}",
    "እንኳን ደስ አለዎት! 50,000 ብር አሸንፈዋል። ለመውሰድ እዚህ ይጫኑ {link}",
    "የቴሌብር አካውንትዎ ችግር አለበት፣ አሁኑኑ ያረጋግጡ {link}",
    "ውድ ደንበኛ፣ ካርድዎ ይዘጋል። ፒን ኮድዎን ለማደስ ይህን ሊንክ ይጠቀሙ {link}",
    "የባንክ አካውንትዎ በአስቸኳይ ማረጋገጫ ይፈልጋል፣ አካውንት ቁጥርዎን ያስገቡ {link}",
    "ይህ የመጨረሻ ማስጠንቀቂያ ነው! ሂሳብዎ በ24 ሰዓት ውስጥ ይዘጋል {link}",
    "ከኢትዮ ቴሌኮም፡ ነጻ ጥቅል አሸንፈዋል፣ አሁኑኑ ይጠይቁ {link}",
    "ሽልማትዎን ለመቀበል የግል መረጃዎን ያረጋግጡ {link}",
    "የሲቢኢ አካውንትዎ ታግዷል። ለማስከፈት የይለፍ ቃልዎን ያስገቡ {link}",
    "በአስቸኳይ! የደመወዝ ክፍያዎ ተይዟል፣ አካውንትዎን ያረጋግጡ {link}",
]

phishing_english = [
    "URGENT: Your account will be suspended today. Verify now {link}",
    "Congratulations! You've won 50,000 birr. Claim your prize here {link}",
    "Your CBE account has been locked. Enter your password to unlock {link}",
    "Dear customer, your card will expire today. Update your PIN at {link}",
    "Final warning: your telebirr wallet will be deactivated. Confirm identity {link}",
    "You have a pending refund of 15,000 ETB. Click to claim {link}",
    "Security alert: unusual login detected. Verify your account immediately {link}",
    "Your package could not be delivered. Confirm your address and pay a small fee {link}",
    "Action required: your Ethio Telecom SIM will be deactivated. Verify now {link}",
    "You are selected for a free scholarship. Submit your account details {link}",
]

phishing_mixed = [
    "Selam! Hisabwo yitagedal!!! Ahununu password'wo yagibu {link}",
    "Dear customer, telebirr account'wo problem alebet, verify ያድርጉ {link}",
    "Congratulations! 50000 birr አሸንፈዋል, claim it here {link}",
    "Urgent: card'wo yizegal, pin code'wo lemaddes ይህን ሊንክ ይጫኑ {link}",
    "Ethio telecom free bundle አሸንፈዋል, click here to claim {link}",
    "Account'wo ይታገዳል today, verify now by clicking {link}",
    "Hello, your cbe account taagedwal, inter password now {link}",
    "Zare limit new, confirm your account number here {link}",
]

phishing_links = [
    "http://telebirr-verify.com",
    "http://cbe-secure-login.net",
    "bit.ly/claim-now",
    "http://ethiotelecom-bonus.com",
    "http://dashenbank-update.com",
    "tinyurl.com/verify-account",
    "http://awashbank-alert.com",
    "http://account-confirm-et.com",
]

# ---------------------------------------------------------------------
# LEGITIMATE MESSAGE TEMPLATES
# ---------------------------------------------------------------------

legit_amharic = [
    "ሰላም እንዴት ነህ? ነገ እንገናኝ?",
    "ፕሮጀክቱን መቼ እንጨርሰዋለን?",
    "እናቴ ደውላ ነበር፣ መልሰህ ደውልላት",
    "ስብሰባው ከሰዓት በኋላ 3 ሰዓት ይጀምራል",
    "ምሳ አብረን እንብላ?",
    "ዛሬ ክፍል ትመጣለህ?",
    "ፋይሉን ልኬልሃለሁ፣ አግኝተኸዋል?",
    "ደህና ሁን፣ በሰላም ደርስ",
    "ፈተናው ውጤት መቼ ይወጣል?",
    "እንኳን ደስ አለህ ለውጤትህ!",
    "ነገ የቤተሰብ ስብሰባ አለን፣ ና",
    "መጽሐፉን መልሰህልኛል?",
    "ስልክህ ለምን ዝግ ነው?",
    "ጤና ይስጥልኝ፣ ደህና አደርክ?",
    "ፕሮጀክቱ ጥሩ እየሄደ ነው፣ አመሰግናለሁ",
    "ነገ ከትምህርት ቤት በኋላ እንገናኝ",
    "ወንድሜ ነገ ይመጣል ከአዲስ አበባ",
    "እራት ልታበስል ትችላለህ?",
    "ያንን ፋይል ለምን ያህል ጊዜ ያስፈልገኛል?",
    "በጣም አመሰግናለሁ ለእርዳታህ",
]

legit_english = [
    "Hey, are we still on for lunch tomorrow?",
    "Can you send me the report by end of day?",
    "Thanks for your help with the project yesterday.",
    "The meeting has been moved to 3pm.",
    "Happy birthday! Hope you have a great day.",
    "Let's catch up this weekend.",
    "I've attached the notes from today's class.",
    "Can you review this document when you get a chance?",
    "See you at the gym later?",
    "Great job on the presentation today!",
    "Can you pick up some groceries on your way home?",
    "The professor pushed the deadline to Friday.",
    "I'll be a bit late to class, save me a seat.",
    "Did you finish the assignment for tomorrow?",
    "Let's grab coffee and go over the slides.",
    "Thanks for lending me your notes last week.",
    "My internet is down, can we reschedule the call?",
    "I really enjoyed the workshop today.",
    "Can you double check this code before I push it?",
    "Looking forward to the weekend trip!",
]

legit_mixed = [
    "Selam, nege class tamelesalesh?",
    "Meeting'u kesaat 3 new, be ready please",
    "Exam result meche yiweta?",
    "Thanks betam, lesew hulu negeregn",
    "Project'u yemiwed document lakihugn",
    "Dehna neh? Really miss our chats",
    "Kezi sat afer limlash, tinish ayzosh",
    "Nege party aleni, tamelesalesh?",
    "Homework'u betam kebad neww",
    "Café alfign, nege injimera?",
    "Teacher'u assignment'u postponed argelech",
    "Betsebkoch neger neber, dehna neh?",
]

LANG_MAP = {
    "amharic": "am",
    "english": "en",
    "mixed": "mixed",
}


def build_rows():
    rows = []

    # Phishing - expand each template with a few different links for variety
    for template in phishing_amharic:
        for link in random.sample(phishing_links, 3):
            rows.append((template.format(link=link), "phishing", "am"))
    for template in phishing_english:
        for link in random.sample(phishing_links, 3):
            rows.append((template.format(link=link), "phishing", "en"))
    for template in phishing_mixed:
        for link in random.sample(phishing_links, 3):
            rows.append((template.format(link=link), "phishing", "mixed"))

    # Some phishing messages with NO link, to avoid the model only keying on URLs
    no_link_phishing = [
        ("ሂሳብዎ ይታገዳል፣ አሁኑኑ ፒን ኮድዎን በመልዕክት ይላኩልኝ", "am"),
        ("Please reply with your OTP code to confirm your identity", "en"),
        ("Send your password now to avoid account suspension", "en"),
        ("Yikerta, ahun pin code'wo በ sms ላክልኝ", "mixed"),
    ]
    for text, lang in no_link_phishing:
        rows.append((text, "phishing", lang))

    # Legit - repeat with slight variation markers to pad the dataset a bit
    for text in legit_amharic:
        rows.append((text, "legit", "am"))
    for text in legit_english:
        rows.append((text, "legit", "en"))
    for text in legit_mixed:
        rows.append((text, "legit", "mixed"))

    # Legit messages that mention brands/money but are NOT phishing
    # (important so the model doesn't just learn "bank word = phishing")
    tricky_legit = [
        ("I just opened a CBE account, the process was quick.", "en"),
        ("Telebirr worked fine for my payment today.", "en"),
        ("ዛሬ ከባንክ ብር አወጣሁ ለቤት ኪራይ", "am"),
        ("Dashen bank branch'u yet new alu?", "mixed"),
        ("I'm meeting the bank manager tomorrow about a loan.", "en"),
        ("ለትምህርት ቤት ክፍያ ብር ላክሁ", "am"),
        ("Awash bank new branch opened near campus.", "en"),
        ("ትላንት ለቴሌብር ደንበኛ አገልግሎት ደወልኩ፣ በጣም ረድተውኛል", "am"),
        ("I won a small prize at the university raffle, so happy!", "en"),
        ("ነገ ከባንክ ጋር ቀጠሮ አለኝ ለስራ ፈቃድ", "am"),
    ]
    for text, lang in tricky_legit:
        rows.append((text, "legit", lang))


    # ------------------------------------------------------------------
    # REALISTIC LEGITIMATE MESSAGES (bank / telecom alerts, OTPs, bills,
    # congratulations, security tips) and SCAMS WRITTEN IN THE SAME STYLE.
    # Without these, a model trained on casual chat learns "mentions a bank
    # or birr = phishing" and raises false alarms on real bank SMS.
    # NOTE: written by an AI assistant from typical patterns, not collected
    # from real messages. Have a native speaker proofread the Amharic ones.
    # ------------------------------------------------------------------
    BANKS = ["CBE", "Dashen Bank", "Awash Bank", "Bank of Abyssinia", "Zemen Bank", "Nib Bank", "telebirr"]
    NAMES = ["Abebe", "Selam", "Mulu", "Dawit", "Hanna", "Yonas", "Tigist", "Kebede", "Meron", "Samuel"]
    MONTHS = ["August", "September", "October", "November", "December"]
    EVENTS = ["graduation", "new job", "promotion", "wedding", "exam results", "new baby", "new home"]
    HOLIDAYS = ["new year", "Easter", "Christmas", "Eid", "birthday"]

    def amt():
        return random.choice(["50.00", "120", "250.00", "500", "800.00", "1,250", "2,000.00", "3,500", "7,000.00", "15,300"])

    def fill(t):
        return t.format(
            bank=random.choice(BANKS), amt=amt(), bal=amt(), name=random.choice(NAMES),
            date=random.choice(["12/10/2026", "15 Oct", "30/11/2026", "the 20th", "Friday"]),
            txid="".join(random.choice("ABCDEFGHJKLMNPQRSTUVWXYZ0123456789") for _ in range(8)),
            gb=random.choice(["1", "2", "5", "10"]), otp=str(random.randint(100000, 999999)),
            month=random.choice(MONTHS), event=random.choice(EVENTS), holiday=random.choice(HOLIDAYS),
            link=random.choice(phishing_links))

    legit_tx_en = [
        "{bank}: Your account has been credited with {amt} ETB. Available balance: {bal} ETB.",
        "{bank}: A debit of {amt} ETB was made on your account on {date}. Balance: {bal} ETB.",
        "Your telebirr transfer of {amt} Birr to {name} was successful. Transaction ID {txid}.",
        "You have received {amt} Birr from {name} via telebirr. Your balance is {bal} Birr.",
        "Your Ethio telecom {gb}GB data package is active until {date}.",
        "Your airtime balance is {amt} Birr. Dial *804# to check your packages.",
        "Your one-time code is {otp}. Do not share it with anyone. It is valid for 5 minutes.",
        "Your {bank} statement for {month} is ready. You can collect it at any branch.",
        "Reminder: your loan installment of {amt} ETB is due on {date}. Please visit your nearest branch.",
        "Your debit card is ready for pick-up at the {bank} branch.",
        "Your water bill of {amt} Birr is due on {date}. Pay at any utility office.",
        "Thank you for your payment of {amt} ETB. Receipt number {txid}.",
        "Security tip from {bank}: never share your PIN or password with anyone.",
        "{bank} will never ask for your PIN or OTP by phone or message.",
        "Congratulations on your {event}! So happy for you.",
        "Happy {holiday}! Wishing you and your family all the best.",
        "Congratulations {name}, you passed the course. Well done!",
    ]
    legit_tx_am = [
        "ሂሳብዎ ላይ {amt} ብር ገቢ ተደርጓል። ቀሪ ሂሳብ {bal} ብር።",
        "ከሂሳብዎ {amt} ብር ተቀንሷል። ቀሪ ሂሳብ {bal} ብር።",
        "{name} የላኩልዎት {amt} ብር ደርሶዎታል።",
        "የ{gb} ጊባ ጥቅልዎ እስከ {date} ድረስ ነው።",
        "የባንክ መግለጫዎ ተዘጋጅቷል፣ ከማንኛውም ቅርንጫፍ መውሰድ ይችላሉ።",
        "ባንካችን ፒን ኮድዎን በጭራሽ አይጠይቅም።",
        "ለማንም የይለፍ ቃልዎን አይንገሩ።",
        "የውሃ ክፍያዎ {amt} ብር እስከ {date} ድረስ መከፈል አለበት።",
        "እንኳን ደስ አለህ፣ ፈተናውን አለፍክ!",
    ]
    legit_tx_mixed = [
        "Selam, {amt} birr telebirr lakilign please",
        "Telebirr lay {amt} birr gebtual, thanks",
        "Betam amesegnalehu, {amt} birr deresegn",
        "Congratulations betam, ye exam result tiru neww!",
    ]
    scam_tx_en = [
        "{bank}: Your account has been credited with {amt} ETB by mistake. Click {link} to return it.",
        "{bank}: A debit of {amt} ETB is pending. If this was not you, confirm your PIN at {link} now.",
        "Your telebirr wallet has received {amt} Birr. Verify your identity within 24 hours at {link} to release it.",
        "{bank}: Unusual activity detected. Send the OTP you received to keep your account active.",
        "Your {bank} card will be blocked today. Update your details at {link}.",
        "You have been selected for a {amt} Birr reward from {bank}. Reply with your PIN to receive it.",
        "{bank} security alert: your account is suspended. Verify now at {link}",
        "Congratulations! You won {amt} Birr from {bank}. Claim your prize now: {link}",
    ]
    scam_tx_am = [
        "{bank}: በሂሳብዎ ላይ ያልተለመደ እንቅስቃሴ ተገኝቷል። ወዲያውኑ ፒን ኮድዎን ያስገቡ {link}",
        "{bank}: ሂሳብዎ ታግዷል። ለማስከፈት አካውንት ቁጥርዎን ያስገቡ {link}",
        "እንኳን ደስ አለዎት! {amt} ብር ሽልማት አሸንፈዋል። ለመቀበል ይጫኑ {link}",
    ]
    scam_tx_mixed = [
        "Selam, {bank} hisabwo yitagedal. PIN'wo ahunu yilaku {link}",
        "Congratulations! {amt} birr aShenifual, claim here {link}",
    ]

    seen = set(r[0] for r in rows)
    def add(templates, label, lang, n):
        for t in templates:
            for _ in range(n):
                text = fill(t)
                if text not in seen:
                    seen.add(text); rows.append((text, label, lang))

    add(legit_tx_en, "legit", "en", 4)
    add(legit_tx_am, "legit", "am", 4)
    add(legit_tx_mixed, "legit", "mixed", 3)
    add(scam_tx_en, "phishing", "en", 3)
    add(scam_tx_am, "phishing", "am", 3)
    add(scam_tx_mixed, "phishing", "mixed", 3)

    random.shuffle(rows)
    return rows


def main():
    rows = build_rows()
    with open("labeled_messages.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label", "language"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to labeled_messages.csv")
    phishing_count = sum(1 for r in rows if r[1] == "phishing")
    legit_count = sum(1 for r in rows if r[1] == "legit")
    print(f"Phishing: {phishing_count}  Legit: {legit_count}")


if __name__ == "__main__":
    main()
