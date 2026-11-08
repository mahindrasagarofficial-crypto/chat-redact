"""Tests for chat-redact. Run with:  python -m pytest  (or: python test_chat_redact.py)"""

from pathlib import Path

from chat_redact import luhn_ok, redact_chat, redact_text, verhoeff_ok

SAMPLE = Path(__file__).parent / "examples" / "sample_chat.txt"


def r(text, **kw):
    return redact_text(text, **kw)


# ---- things that MUST be removed -------------------------------------------------

def test_indian_mobile_formats():
    for s in ["98200 12345", "9820012345", "+91 98200 12345", "+91-9820012345", "09820012345", "919820012345"]:
        assert r(f"call {s} now") == "call [PHONE] now", s


def test_international_phone():
    assert r("UK office +44 20 7946 0958") == "UK office [PHONE]"


def test_email():
    assert r("mail priya.s@gmail.com today") == "mail [EMAIL] today"


def test_upi_id_not_confused_with_email():
    assert r("pay ramesh.patil@okhdfcbank") == "pay [UPI ID]"
    assert r("pay 9820012345@ybl") == "pay [UPI ID]"
    assert r("write to a@b.com") == "write to [EMAIL]"


def test_aadhaar_checksum():
    assert r("Aadhaar 8128 0619 2057") == "Aadhaar [AADHAAR]"
    assert r("ID 812806192057") == "ID [AADHAAR]"


def test_pan_gstin_ifsc():
    assert r("PAN ABCDE1234F") == "PAN [PAN]"
    assert r("GST 27ABCDE1234F1Z5") == "GST [GSTIN]"
    assert r("IFSC HDFC0001234") == "IFSC [IFSC]"


def test_bank_account_after_keyword():
    assert r("A/C No 50100234567812") == "A/C No [BANK ACCOUNT]"
    assert r("account number: 1234 5678 9012") == "account number: [BANK ACCOUNT]"


def test_card_number_luhn():
    assert r("card 4111 1111 1111 1111") == "card [CARD NUMBER]"
    assert r("card 4111-1111-1111-1111") == "card [CARD NUMBER]"


def test_secrets():
    assert r("password is Shop@123") == "password is [PASSWORD]"
    assert r("pwd: tiger#99") == "pwd: [PASSWORD]"
    assert r("OTP 482913 came") == "OTP [OTP] came"
    assert r("cvv 123") == "cvv [CVV]"
    assert r("upi pin 4321") == "upi pin [PIN]"


def test_ip_address():
    assert r("server 192.168.1.45 down") == "server [IP ADDRESS] down"


# ---- things that must be LEFT ALONE ---------------------------------------------

def test_business_numbers_untouched():
    keep = [
        "Order of 120 pieces, rate 340, total 40,800",
        "sent ₹45,000 today",
        "delivery on 15/10/26 at 10:30",
        "pass 2 boxes to Ramesh",
        "invoice no 4521",
        "pincode 400601",
    ]
    for s in keep:
        assert r(s) == s, s


def test_random_12_digits_not_aadhaar():
    # fails Verhoeff, so it is not treated as Aadhaar
    assert verhoeff_ok("812806192057")
    assert not verhoeff_ok("812806192058")
    assert "[AADHAAR]" not in r("ref 8128 0619 2058")


def test_luhn():
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")


# ---- whole chat behaviour --------------------------------------------------------

def test_timestamps_and_names_kept_by_default():
    out = redact_chat(SAMPLE.read_text(encoding="utf-8")).text
    assert out.startswith("12/10/26, 10:40 - Ramesh Patil: Good morning team")
    assert "[AADHAAR]" in out and "[CARD NUMBER]" in out
    assert "8128" not in out and "4111" not in out and "Shop@123" not in out


def test_hide_names():
    res = redact_chat(SAMPLE.read_text(encoding="utf-8"), hide_names=True)
    assert "Ramesh" not in res.text and "Priya" not in res.text and "Anil" not in res.text
    assert "Person 1: Good morning team" in res.text
    assert "Ignore it Person 3." in res.text


def test_ios_export_format():
    chat = "[12/10/26, 10:42:01 AM] Priya Shah: call me 9820012345\n"
    assert redact_chat(chat).text == "[12/10/26, 10:42:01 AM] Priya Shah: call me [PHONE]\n"


def test_multiline_message():
    chat = "12/10/26, 10:42 - Priya: details below\nemail priya@shop.in\n"
    assert redact_chat(chat).text == "12/10/26, 10:42 - Priya: details below\nemail [EMAIL]\n"


def test_counts_and_strict_mode():
    res = redact_chat("12/10/26, 10:42 - A: ref 123456789012345\n", strict=True)
    assert "[NUMBER]" in res.text and res.counts["NUMBER"] == 1


if __name__ == "__main__":
    import inspect, sys
    fails = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and inspect.isfunction(fn):
            try:
                fn(); print("ok  ", name)
            except AssertionError as e:
                fails += 1; print("FAIL", name, e)
    sys.exit(1 if fails else 0)
