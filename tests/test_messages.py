"""
Sanity-check the whole detector on lists of messages (only misses are printed).

Run from the project root:
    python tests/test_messages.py

Each case says what we EXPECT:
    "safe"  -> verdict should be Safe
    "flag"  -> verdict should be Suspicious or Dangerous
    "danger"-> verdict should be Dangerous

Add your own messages at the bottom of CASES, especially ones you receive
or that classmates suggest. Every miss you find and fix makes the demo stronger.

Note: certificate checks are skipped here so results are the same offline.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import link_analyzer  # noqa: E402
link_analyzer.check_certificate = lambda domain, timeout=3.0: {
    "valid": None, "reason": "skipped in tests"}

from scoring import get_verdict  # noqa: E402

CASES = [
    # ---------- scams that SHOULD be flagged ----------
    ("flag",   "congratulation you win 100 dollar"),
    ("flag",   "You have won a free iPhone! Reply with your full name to claim"),
    ("flag",   "Your telebirr account has been suspended. Send your PIN to restore it"),
    ("danger", "URGENT: your CBE account will be blocked within 24 hours. Verify now at cbe-secure-login.net"),
    ("flag",   "Dear customer you are selected for a free scholarship, submit your account details"),
    ("danger", "Congratulations! You've won 50000 birr, claim now: bit.ly/xyz123"),
    ("flag",   "Final notice: confirm your identity or your SIM will be deactivated"),
    ("flag",   "Please share your OTP code so we can cancel the wrong transfer"),
    ("danger", "ውድ ደንበኛ፣ የቴሌብር ሂሳብዎ ታግዷል። ፒን ኮድዎን ይላኩ http://telebirr-verify.com"),
    ("flag",   "እንኳን ደስ አለዎት! የ10,000 ብር ሎተሪ አሸንፈዋል። ሽልማትዎን ለመቀበል ይደውሉ"),
    ("danger", "Selam, account'wo yitagedal, ahunu click yaregu http://ethiotelecom-bonus.com"),
    ("flag",   "Ethio telecom free bundle you win, claim your prize today"),
    ("flag",   "Your package is waiting, pay small fee at tinyurl.com/pkg-fee urgent"),
    ("flag",   "Security alert: your account is locked. Confirm your account details"),

    # ---------- normal messages that should stay Safe ----------
    ("safe",   "Hi, are we still meeting tomorrow at 5?"),
    ("safe",   "Can you send me the lecture notes when you get a chance?"),
    ("safe",   "I forgot my wifi password, do you remember it?"),
    ("safe",   "Happy birthday! Wishing you a wonderful year ahead"),
    ("safe",   "Telebirr worked fine for my payment today"),
    ("safe",   "I'm going to the bank tomorrow to ask about a loan"),
    # Known borderline: "expires soon" is a common scam phrase, so this lands right
    # at the Suspicious threshold (30.4). A real trade-off: catch more scams vs. more false alarms.
    ("safe",   "My phone number expires soon? No, I just topped up"),
    ("safe",   "Great presentation today, the judges loved it"),
    ("safe",   "Check the project repo here https://github.com/mimi/phishing-shield"),
    ("safe",   "ነገ ማታ ለእራት ቤታችን ኑ"),
    ("safe",   "የቤት ስራውን ጨርሰሃል?"),
    ("safe",   "ዛሬ በቴሌብር ብር ልኬልሃለሁ፣ ደርሶሃል?"),
    ("safe",   "Selam, nege class tamelesalesh?"),
    ("safe",   "I won the school chess tournament yesterday!"),
]


# ---------------------------------------------------------------------------
# REALISTIC LEGITIMATE MESSAGES + MATCHING SCAMS ("dev" set).
# These were used to find and fix false alarms (bank alerts, OTP notices,
# "congratulations", security warnings), so they are regression tests, NOT a
# fair measure of accuracy.
# ---------------------------------------------------------------------------
DEV = [
    ('safe' , 'Dear customer, your telebirr account has been credited with 500.00 Birr from Abebe Kebede. Your new balance is 1,250.00 Birr.'),
    ('safe' , 'CBE: Your account 1000XXXX1234 has been debited 2,000.00 ETB on 12/10/2026. Balance: 15,300.50 ETB.'),
    ('safe' , 'Your Ethio telecom 5GB data package has been activated and will expire on 30/11/2026.'),
    ('safe' , 'Your OTP is 482913. Do not share this code with anyone. It expires in 5 minutes.'),
    ('safe' , 'ውድ ደንበኛ፣ የቴሌብር ሂሳብዎ 500 ብር ገቢ ተደርጓል።'),
    ('safe' , 'Dashen Bank: your loan payment of 3,500 ETB is due on 15 Oct. Please visit your nearest branch.'),
    ('safe' , 'Your telebirr transaction was successful. Details: https://www.ethiotelecom.et/telebirr'),
    ('safe' , 'Awash Bank: your new debit card is ready for pick-up at the branch.'),
    ('safe' , 'Congratulations on your graduation! So proud of you.'),
    ('safe' , 'Congratulations! You passed the exam, well done.'),
    ('safe' , 'Congratulations on winning the competition!'),
    ('safe' , 'Never share your PIN or password with anyone, including bank staff.'),
    ('safe' , "Reminder: registration closes on Friday. Please complete it at the registrar's office."),
    ('safe' , 'ከባንክ ብር አወጣሁ ለቤት ኪራይ'),
    ('flag' , 'Congratulations! You won 100,000 birr in the telebirr lottery. Send your PIN to claim.'),
    ('flag' , 'Dear customer your CBE account is suspended. Verify now: http://cbe-verify.net'),
    ('flag' , 'Your Ethio telecom SIM will be deactivated. Click bit.ly/3xQ9zT7 to confirm your details.'),
    ('flag' , 'ሂሳብዎ ታግዷል። አሁኑኑ የይለፍ ቃልዎን ይላኩ'),
    ('flag' , 'You have won a free iPhone, reply with your full name and account number'),
]

# ---------------------------------------------------------------------------
# HELD-OUT SET: written before the fixes and run once afterwards (20/20).
# Caveat: it is small, written by the same author in the same style as the
# training data, and one logic bug (negation) was fixed after reading its
# results. Treat it as encouraging, not as real-world accuracy.
# ---------------------------------------------------------------------------
HELD_OUT = [
    ('safe' , 'Your telebirr payment of 150.00 Birr to Selam Cafe was successful. Transaction ID: 8K3L9X2.'),
    ('safe' , 'Bank of Abyssinia: Salary of 18,000.00 ETB has been deposited to your account.'),
    ('safe' , 'Your Ethio telecom airtime balance is 23.50 Birr. Dial *804# to recharge.'),
    ('safe' , 'Hi Sara, your appointment is confirmed for Monday at 10am.'),
    ('safe' , "Congratulations on your new job! Let's celebrate this weekend."),
    ('safe' , 'Happy new year! Wishing you health and happiness.'),
    ('safe' , 'Security tip: never give your OTP or password to anyone, even if they say they are from the bank.'),
    ('safe' , 'ሰላም፣ የባንክ ሂሳብዎ ላይ 2,000 ብር ገቢ ተደርጓል። ቀሪ ሂሳብ 5,400 ብር።'),
    ('safe' , 'Your electricity bill of 320 Birr is due on the 20th. Pay at any utility office.'),
    ('safe' , 'Zemen Bank: Your statement for September is ready. Visit any branch to collect it.'),
    ('safe' , 'Please find the meeting notes attached. Let me know if you have questions.'),
    ('safe' , 'ነገ ክፍል ውስጥ እንገናኝ፣ የቡድን ስራውን እንጨርሳለን'),
    ('flag' , 'Dear user, your Dashen Bank account has been limited. Confirm your identity at http://dashen-secure.info within 24 hours.'),
    ('flag' , 'You have been selected for a 20,000 birr telebirr reward. Send your PIN to receive it.'),
    ('flag' , 'Urgent: unusual login detected on your account. Reply with the OTP we sent you to avoid suspension.'),
    ('flag' , 'ኢትዮ ቴሌኮም፡ የ5000 ብር ሽልማት አሸንፈዋል! ለመቀበል ይህን ሊንክ ይጫኑ http://ethio-bonus.top'),
    ('flag' , 'Your parcel is held at customs. Pay 200 birr at tinyurl.com/etpost-fee to release it.'),
    ('flag' , "Selam, CBE hisabwo yitagedal. PIN'wo lemakeles ahunu yilaku."),
    ('flag' , 'Free 10GB data from Ethio telecom! Click to activate your gift: http://free-data-et.xyz'),
    ('flag' , 'Final notice: your telebirr wallet will be closed today unless you verify your account.'),
]

# Warnings vs. requests: "never share your PIN" is advice, "send your PIN" is a scam.
NEGATION = [
    ("safe",   "Never share your PIN with anyone."),
    ("safe",   "Please do not share your password with anyone."),
    ("safe",   "Do not ever give your OTP to anyone, even the bank."),
    ("flag",   "Reply with the OTP we sent you to avoid suspension."),
    ("flag",   "Do not ignore this message and send your PIN now"),
    ("flag",   "Send your PIN without delay"),
]

SECTIONS = [("Original cases", CASES), ("Realistic legit + matching scams (dev)", DEV),
            ("Held-out set", HELD_OUT), ("Warnings vs. requests", NEGATION)]


def passes(expect, verdict):
    if expect == "safe":
        return verdict == "Safe"
    if expect == "flag":
        return verdict in ("Suspicious", "Dangerous")
    if expect == "danger":
        return verdict == "Dangerous"
    raise ValueError(expect)


def main():
    total = good_total = 0
    for title, cases in SECTIONS:
        print(f"\n{title}")
        print(f"{'':4}{'expect':<8}{'verdict':<11}{'score':>6}  message")
        print("-" * 90)
        ok_section = 0
        for expect, text in cases:
            v = get_verdict(text)
            good = passes(expect, v["verdict"])
            ok_section += good
            if not good:
                print(f"{'MISS':<4}{expect:<8}{v['verdict']:<11}{v['final_score']:>6}  {text[:60]}")
        print(f"-> {ok_section}/{len(cases)} as expected")
        total += len(cases); good_total += ok_section
    print(f"\nTOTAL: {good_total}/{total} as expected")
    sys.exit(0 if good_total == total else 1)


if __name__ == "__main__":
    main()
