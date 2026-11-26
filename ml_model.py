"""Small, offline Bernoulli Naive Bayes model for English scam-message patterns.

The intentionally small curated corpus makes this a transparent demo model,
not a replacement for a reviewed production dataset or human judgment.
"""
from __future__ import annotations

import math
import re
from collections import Counter


TRAINING_DATA = [
    (1, "Your bank account is blocked today update KYC immediately at this link"),
    (1, "Your SBI account will be suspended verify KYC now to avoid closure"),
    (1, "Read out the OTP we sent to unblock your card"),
    (1, "Share your verification code with bank support to secure your account"),
    (1, "You won a lottery prize pay a processing fee to claim your reward"),
    (1, "Congratulations you are selected for a prize pay tax to release it"),
    (1, "Pay a refundable registration fee to start this work from home job"),
    (1, "Earn money per day by liking videos pay joining fee first"),
    (1, "Your parcel is held at customs pay redelivery fee today"),
    (1, "Pay customs charge to release your gift parcel now"),
    (1, "Scan this QR code to receive your payment"),
    (1, "Approve this UPI collect request and enter your PIN for refund"),
    (1, "Install AnyDesk so our bank agent can help you reverse the payment"),
    (1, "Download this APK to update your bank account or it will be blocked"),
    (1, "Your electricity will be disconnected tonight unless you pay this bill"),
    (1, "Pay immediately to stop power disconnection"),
    (1, "Guaranteed returns of 300 percent with no risk join our stock tips group"),
    (1, "Invest today for risk free guaranteed daily profit"),
    (1, "Buy five gift cards urgently and send me the codes I will reimburse you"),
    (1, "Your manager needs Amazon gift card codes immediately"),
    (1, "This is police digital arrest stay on video call and transfer money"),
    (1, "Your parcel contains illegal items pay bail to avoid arrest"),
    (1, "Your SIM will be deactivated press one and complete KYC now"),
    (1, "Your bank card is blocked call this number and tell us the OTP"),
    (1, "Pay a small advance to receive your loan approval today"),
    (1, "Your account will close tonight click this link and verify password"),
    (1, "Send money to this new UPI ID to unlock your cashback reward"),
    (1, "You have won a phone pay delivery charges to receive the prize"),
    (1, "Your tax refund is ready share your bank login to claim it"),
    (1, "Urgent transfer needed I am your boss and cannot talk right now"),
    (1, "Pay refundable laptop kit deposit to confirm your job offer"),
    (1, "Your KYC has expired send OTP to keep your bank account active"),
    (1, "Click shortened link to claim your cash prize before midnight"),
    (1, "A courier agent needs your card details to release the package"),
    (1, "Share screen with our support team to cancel the fraudulent transfer"),
    (1, "Pay refundable customs fee before we deliver your gift"),
    (1, "Your wallet is frozen verify your PIN with the agent"),
    (1, "Congratulations selected for a work from home job pay training fee"),
    (1, "Send an advance payment now to reserve your guaranteed investment"),
    (1, "Your electricity bill is overdue pay through this suspicious link today"),
    (0, "Your OTP for bank login is 482910 do not share it with anyone"),
    (0, "Your account statement is ready in the official banking app"),
    (0, "Your package arrives today track it inside the shopping app"),
    (0, "College fee receipt is attached contact the accounts office with questions"),
    (0, "Your electricity bill is due next week pay through the official app"),
    (0, "A payment was made with your card if it was not you call the number on the back"),
    (0, "Your bank will never ask you for an OTP or PIN over the phone"),
    (0, "KYC was completed at your bank branch keep the receipt for your records"),
    (0, "The parcel has shipped and can be tracked in the seller app"),
    (0, "Your salary was credited today check the balance in your bank app"),
    (0, "You can receive money by sharing your UPI ID never share your PIN"),
    (0, "I sent you money please check your UPI transaction history"),
    (0, "The school fee is due on Friday contact the school office"),
    (0, "Your insurance premium is due on the date shown in the official app"),
    (0, "The delivery agent will call when they reach your address"),
    (0, "Your train ticket is confirmed see details in the railway app"),
    (0, "We received your payment and attached the receipt"),
    (0, "The bank will never ask you to install remote access software"),
    (0, "Please call me when you are free no payment is needed"),
    (0, "I will pay the advance after we sign the agreement"),
    (0, "Your electricity connection is active and your last bill is paid"),
    (0, "The company will not ask job applicants to pay a registration fee"),
    (0, "The package is available for pickup at the local post office"),
    (0, "Your refund was sent to your original payment method"),
    (0, "The bank sent a login alert use the official app if this was not you"),
    (0, "A friend shared a photo with you in the family group"),
    (0, "Your monthly statement is available for download from the bank website"),
    (0, "The shop accepted your UPI payment and gave you a receipt"),
    (0, "Your appointment is confirmed for tomorrow at ten in the morning"),
    (0, "Please verify the amount on your college invoice before paying"),
    (0, "Your account remains active and no action is needed"),
    (0, "We have received your application and will contact you next week"),
    (0, "Your parcel delivery has been rescheduled in the official courier app"),
    (0, "The bank branch is open until four pm on weekdays"),
    (0, "You can check your tax refund status on the government portal"),
    (0, "The payment request is from our verified store account"),
    (0, "Your mobile recharge was successful and the receipt is ready"),
]

TOKEN_RE = re.compile(r"[a-z][a-z0-9']{1,}")
STOP_WORDS = set("""
    a an and are as at be been before by can did do for from had has have he her
    here him his i if in inside is it its me my no of on one or our out she so
    the their them they this to up us was we were will with you your
    please today app bank
""".split())


def _features(text: str) -> set[str]:
    words = [w for w in TOKEN_RE.findall(str(text).lower()) if w not in STOP_WORDS]
    result = set(words)
    result.update(f"{a}_{b}" for a, b in zip(words, words[1:]))
    return result


def _fit():
    docs = {0: [], 1: []}
    for label, text in TRAINING_DATA:
        docs[label].append(_features(text))
    vocab = set().union(*docs[0], *docs[1])
    # Each feature is counted once per document; this is Bernoulli Naive Bayes.
    doc_freq = {label: Counter(f for row in rows for f in row) for label, rows in docs.items()}
    return docs, vocab, doc_freq


_DOCS, _VOCAB, _DOC_FREQ = _fit()
_SCAM_DOCS = len(_DOCS[1])
_SAFE_DOCS = len(_DOCS[0])
_PRIOR = math.log(_SCAM_DOCS / _SAFE_DOCS)


def classify(text: str) -> dict | None:
    """Return a conservative scam probability, or None for weak language evidence."""
    letters = [ch for ch in str(text) if ch.isalpha()]
    latin_ratio = sum(ch.isascii() for ch in letters) / max(1, len(letters))
    if len(letters) < 4 or latin_ratio < 0.65:
        return None
    features = _features(text)
    known = features & _VOCAB
    if len(known) < 2:
        return None

    log_odds = _PRIOR
    for feature in known:
        scam_rate = (_DOC_FREQ[1][feature] + 1) / (_SCAM_DOCS + 2)
        safe_rate = (_DOC_FREQ[0][feature] + 1) / (_SAFE_DOCS + 2)
        # Damp highly specific words so a tiny curated corpus cannot dominate.
        delta = math.log(scam_rate / safe_rate)
        log_odds += max(-1.25, min(1.25, delta))
    log_odds = max(-5.0, min(5.0, log_odds * 0.62))
    probability = 1 / (1 + math.exp(-log_odds))
    return {"probability": round(probability * 100), "evidence": len(known)}
