# 🔐 Dynamic AES Encryption API

A **FastAPI** backend that lets you **encrypt** and **decrypt** any text using a secret key.
Even if you don't know anything about cryptography, this guide will help you understand and run the project.

---

## 📖 What Does This Project Do?

Think of it like a **digital safe**:

- You give it some **text** (e.g., `"Hello World"`) and a **secret key**.
- It **locks** the text (encryption) and gives you a scrambled output that nobody can read.
- Later, you use the **same secret key** to **unlock** it (decryption) and get the original text back.

---

## 🧠 How It Works — Simple Explanation

The project uses **three steps** to protect your data:

### Step 1 — Transform the Secret Key (LFSR)
> *"Make the key harder to guess"*

Your secret key is 16 characters (bytes) long.
Before using it, we run it through a **number generator** (called LFSR — think of it like a dice-rolling machine that always rolls the same numbers if you give it the same starting number).

The machine produces **16 random-looking numbers**, and we mix them with your key using a simple **XOR operation** (swapping bits). This gives us a new, stronger "evolved key".

```
Original Key:    [00] [11] [22] [33] ...
LFSR Numbers:    [A3] [7F] [B2] [C1] ...
                   ↕    ↕    ↕    ↕
Evolved Key:     [A3] [6E] [90] [F2] ...   ← this is what actually encrypts your data
```

> ✅ Both sender and receiver compute this automatically — nothing extra needs to be shared.

---

### Step 2 — Pad the Text
> *"Make the text the right size"*

Encryption works on fixed chunks of **16 bytes** at a time.
If your text is not a multiple of 16 bytes, we add extra bytes at the end to fill it up. This is called **padding**.

```
"Hello" (5 bytes)  →  "Hello" + 11 filler bytes  =  16 bytes  ✓
```

---

### Step 3 — Encrypt with AES + IV
> *"Actually lock the text"*

We generate a **random IV** (Initialization Vector — a random 16-byte starter value) every time we encrypt. This ensures that encrypting the **same text twice** gives **different results** each time, which makes it much harder to crack.

Then we encrypt the padded text block by block, where each block uses the previous block's result as part of its encryption:

```
Block 1: Encrypt( PaddedText₁  ⊕  IV         )  →  CipherBlock₁
Block 2: Encrypt( PaddedText₂  ⊕  CipherBlock₁)  →  CipherBlock₂
...and so on
```

The **IV** is returned with the ciphertext so the receiver can decrypt it.

---

### Decryption is the Reverse

```
CipherBlock → Decrypt → XOR with previous block → Original Text
```

The same evolved key is used (computed from the same raw key), so you don't need to send anything extra.

---

## 📁 Project Structure

```
AESPROJECT/
├── main.py                  ← Starts the API server
├── requirements.txt         ← Python packages needed
├── crypto/
│   ├── aes_engine.py        ← Encrypts and decrypts data
│   ├── lfsr.py              ← Generates the pseudorandom numbers
│   └── key_evolution.py     ← Mixes LFSR output with the raw key
├── routes/
│   └── crypto_routes.py     ← Defines the API endpoints
└── schemas/
    └── crypto_schemas.py    ← Validates inputs and outputs
```

---

## ⚙️ Setup & Run Commands

### Step 1 — Make sure Python is installed

```bash
python --version
```

You need **Python 3.9 or higher**.

---

### Step 2 — Create a virtual environment

A virtual environment keeps your project's packages separate from the rest of your computer.

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Mac / Linux:**
```bash
python -m venv venv
source venv/bin/activate
```

> You'll see `(venv)` in your terminal when it's active.

---

### Step 3 — Install required packages

```bash
pip install -r requirements.txt
```

This installs:

| Package | What it does |
|---|---|
| `fastapi` | The web framework that handles API requests |
| `uvicorn` | The server that runs FastAPI |
| `pycryptodome` | Provides the AES encryption algorithm |
| `pydantic` | Validates the data you send to the API |

---

### Step 4 — Start the server

```bash
uvicorn main:app --reload
```

| Flag | Meaning |
|---|---|
| `--reload` | Automatically restarts the server when you change a file |
| `--host 0.0.0.0` | Makes it accessible from any device on your network |
| `--port 8000` | The port number the server runs on |

Once running, open your browser and visit:

| Page | URL |
|---|---|
| 🟢 API is running check | http://localhost:8000 |
| 📘 Interactive API docs (Swagger) | http://localhost:8000/docs |
| 📗 Alternative API docs (ReDoc) | http://localhost:8000/redoc |

---

### Step 5 — Stop the server

Press **Ctrl + C** in the terminal.

---

### Step 6 — Deactivate the virtual environment (when done)

```bash
deactivate
```

---

## 🌐 API Endpoints

### ✅ Health Check

```
GET  http://localhost:8000/
```

**Response:**
```json
{
  "status": "ok",
  "service": "Dynamic AES Encryption API",
  "version": "1.0.0",
  "docs": "/docs"
}
```

---

### 🔒 Encrypt Text

```
POST  http://localhost:8000/crypto/encrypt
```

**What to send (JSON body):**

| Field | Type | Description | Example |
|---|---|---|---|
| `plaintext` | string | The text you want to encrypt | `"Hello World"` |
| `secret_key` | string | A 32-character hex key (= 128-bit key) | `"00112233445566778899aabbccddeeff"` |

> **What is a hex key?** Each pair of hex characters (like `00`, `11`, `AA`) represents one byte.
> A 32-character hex string = 16 bytes = 128-bit key, which is what AES-128 needs.

**Example request:**
```json
{
  "plaintext": "Hello, Dynamic AES!",
  "secret_key": "00112233445566778899aabbccddeeff"
}
```

**Example response:**
```json
{
  "ciphertext": "a3f1c2d4e5b6a7f89c0d1e2f3a4b5c6d...",
  "iv": "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c",
  "message": "Encryption successful."
}
```

> Save **both** `ciphertext` and `iv` — you need them to decrypt later.

---

### 🔓 Decrypt Text

```
POST  http://localhost:8000/crypto/decrypt
```

**What to send (JSON body):**

| Field | Type | Description |
|---|---|---|
| `ciphertext` | string | The scrambled text from the encrypt response |
| `iv` | string | The IV from the encrypt response |
| `secret_key` | string | The **same** 32-character hex key used to encrypt |

**Example request:**
```json
{
  "ciphertext": "a3f1c2d4e5b6a7f89c0d1e2f3a4b5c6d...",
  "iv": "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c",
  "secret_key": "00112233445566778899aabbccddeeff"
}
```

**Example response:**
```json
{
  "plaintext": "Hello, Dynamic AES!",
  "message": "Decryption successful."
}
```

---

## 🧪 Test Using cURL (Command Line)

**Encrypt:**
```bash
curl -X POST http://localhost:8000/crypto/encrypt \
     -H "Content-Type: application/json" \
     -d "{\"plaintext\": \"Hello World\", \"secret_key\": \"00112233445566778899aabbccddeeff\"}"
```

**Decrypt:**
```bash
curl -X POST http://localhost:8000/crypto/decrypt \
     -H "Content-Type: application/json" \
     -d "{\"ciphertext\": \"<paste ciphertext here>\", \"iv\": \"<paste iv here>\", \"secret_key\": \"00112233445566778899aabbccddeeff\"}"
```

Or just use the **Swagger UI** at [http://localhost:8000/docs](http://localhost:8000/docs) — it lets you test everything in your browser with a friendly form.

---

## ❌ Common Errors

| Error | Cause | Fix |
|---|---|---|
| `422 Unprocessable Entity` | `secret_key` is not 32 hex characters | Use exactly 32 hex characters (0–9, a–f) |
| `400 Bad Request` | Wrong key or IV during decryption | Make sure you use the same key and IV from encryption |
| `500 Internal Server Error` | Unexpected server issue | Check the terminal where uvicorn is running |

---

## 🔑 How to Generate a Valid Secret Key

A valid key is any **32-character string made of hex digits** (`0-9`, `a-f`).

**Examples of valid keys:**
```
00112233445566778899aabbccddeeff
deadbeefcafebabe0123456789abcdef
ffffffffffffffffffffffffffffffff
```

**Quick way to generate one in Python:**
```python
import os
print(os.urandom(16).hex())
```

---

## 📦 All Commands — Quick Reference

```bash
# 1. Check Python version
python --version

# 2. Create virtual environment
python -m venv venv

# 3. Activate (Windows)
venv\Scripts\activate

# 3. Activate (Mac/Linux)
source venv/bin/activate

# 4. Install packages
pip install -r requirements.txt

# 5. Start the server
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# 6. Stop the server
# Press Ctrl+C

# 7. Deactivate virtual environment
deactivate

# 8. (Optional) Run on a different port
uvicorn main:app --reload --port 9000
```

---

*Built with ❤️ using FastAPI, AES-128-CBC, and LFSR-based Key Evolution*
