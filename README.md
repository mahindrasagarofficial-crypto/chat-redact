# chat-redact 🔒

**Remove phone numbers, UPI IDs, Aadhaar, PAN, bank details, card numbers and passwords from WhatsApp chat exports, before you paste them into ChatGPT or Claude or share them with anyone.**

Built for Indian business chats, where these details turn up all the time. Free, open source, and nothing leaves your computer.

![tests](https://img.shields.io/badge/tests-18%20passing-brightgreen) ![python](https://img.shields.io/badge/python-3.8%2B-blue) ![dependencies](https://img.shields.io/badge/dependencies-none-lightgrey) ![license](https://img.shields.io/badge/license-MIT-green)

---

## Before → after

```text
Ramesh Patil: Payment please send to A/C No 50100234567812, IFSC HDFC0001234
Priya Shah: Also paid 12,500 by UPI to ramesh.patil@okhdfcbank
Priya Shah: For the new portal my login is priya.s@gmail.com and password is Shop@123
Anil Kumar: Ramesh bhai call me on 98200 12345 or +91 91234-56789
Priya Shah: Courier guy needs my Aadhaar 8128 0619 2057, sending photo
Priya Shah: Order of 120 pieces, rate 340, delivery on 15/10/26. Total 40,800
```

```text
Ramesh Patil: Payment please send to A/C No [BANK ACCOUNT], IFSC [IFSC]
Priya Shah: Also paid 12,500 by UPI to [UPI ID]
Priya Shah: For the new portal my login is [EMAIL] and password is [PASSWORD]
Anil Kumar: Ramesh bhai call me on [PHONE] or [PHONE]
Priya Shah: Courier guy needs my Aadhaar [AADHAAR], sending photo
Priya Shah: Order of 120 pieces, rate 340, delivery on 15/10/26. Total 40,800
```

The private details are gone, but the business information (quantities, rates, totals, dates) stays, so the chat still makes sense to an AI or a colleague.

With `--hide-names`, senders become `Person 1`, `Person 2` and so on, including where their names appear inside messages.

## Install

```bash
pip install git+https://github.com/mahindrasagarofficial-crypto/chat-redact
```

Or just download `chat_redact.py`. It's a single file that uses only the Python standard library.

## Use

1. In WhatsApp, open the chat → ⋮ → **More → Export chat → Without media**. You'll get a `.txt` file.
2. Run:

```bash
chat-redact "WhatsApp Chat with Shop Team.txt" -o clean.txt
```

```text
chat-redact: removed 14 item(s) (phone: 2, upi id: 1, aadhaar: 1, bank account: 1, ...)
```

| Option | What it does |
|---|---|
| `-o FILE` | Save the clean chat to a file (default: print it) |
| `--hide-names` | Replace sender names with Person 1, Person 2, … |
| `--strict` | Also mask any other long number (9+ digits), e.g. order or tracking IDs |
| `--blocks` | Use `██████` instead of `[LABELS]` |
| `-q` | Don't print the summary |

From Python:

```python
from chat_redact import redact_chat, redact_text

print(redact_text("call me on 98200 12345"))        # call me on [PHONE]
result = redact_chat(open("chat.txt").read(), hide_names=True)
print(result.text, result.counts)
```

## What it catches

| Type | Examples | How false matches are avoided |
|---|---|---|
| Indian mobile | `98200 12345`, `+91-9820012345`, `09820012345` | Must start with 6–9 and have 10 digits |
| International phone | `+44 20 7946 0958` | Needs a `+` country code |
| Email | `priya.s@gmail.com` | |
| UPI ID | `ramesh@okhdfcbank`, `9820012345@ybl` | Told apart from emails (no dot in the provider) |
| Aadhaar | `8128 0619 2057` | Must pass the official **Verhoeff checksum** |
| PAN | `ABCDE1234F` | Exact format |
| GSTIN | `27ABCDE1234F1Z5` | Exact format |
| IFSC | `HDFC0001234` | Exact format |
| Bank account | `A/C No 50100234567812` | Only next to words like *A/C*, *account no* |
| Card number | `4111 1111 1111 1111` | Must pass the **Luhn checksum** |
| Password | `password is Shop@123`, `pwd: tiger#99` | Needs a keyword, 4+ characters and a digit or symbol |
| OTP / CVV / PIN | `OTP 482913`, `cvv 123`, `upi pin 4321` | Needs the keyword right before it |
| IP address | `192.168.1.45` | |

Works with both Android (`12/10/26, 10:42 - Name: …`) and iPhone (`[12/10/26, 10:42:01 AM] Name: …`) exports. Timestamps and multi-line messages are kept.

## Limits (please read)

This tool finds details that follow a **pattern**. It cannot understand meaning, so it will **not** catch things like *"my husband's surgery is on Friday"* or a home address typed in words. Always read the output before you share something sensitive. It may also mask a 10-digit order number that looks like a mobile number, which is the safer mistake to make.

## Why I built this

I build AI agents that read business group chats and answer questions from them ([case study](https://github.com/mahindrasagarofficial-crypto/ai-knowledge-agent-case-study)). The first rule of that pipeline is that private details are filtered out **before** anything is stored or sent to an AI. This is that filter as a small, standalone tool, so anyone can use it.

Ideas and pull requests are welcome, especially new Indian ID formats (voter ID, passport, vehicle numbers) and other chat export formats.

## Run the tests

```bash
python -m pytest        # or: python test_chat_redact.py
```

---

Made by **Sagar Mahindra**: [LinkedIn](https://www.linkedin.com/in/sagar-m-902965416) · [Upwork](https://www.upwork.com/freelancers/~01c726d9217f6052ca) · MIT licence
