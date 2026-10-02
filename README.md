# CYBERKIT

> A hacker-themed cybersecurity toolkit that runs entirely in your browser.
>
> **[▶ Try it live](https://aziz4rehman-hue.github.io/cyberkit/)**

No install, no server, no tracking. Open `index.html` and start exploring. Nothing you type ever leaves your machine.

## Features

| Tool | What it does |
|------|--------------|
| **Terminal** | A fake Linux-style shell with commands like `hack`, `sysinfo`, `pw`, `hashid`, `jwt` and `tip` |
| **Password analyzer** | Works out entropy and finds weak patterns (sequences, years, leetspeak, common passwords). Estimates how long the password would take to crack offline (GPU) and online |
| **Hash generator** | MD5, SHA-1, SHA-256, SHA-384, SHA-512 (MD5 implemented from scratch, the rest via WebCrypto) |
| **Hash identifier & cracker** | Guesses the hash type (MD5, NTLM, SHA-*, bcrypt, Argon2, shadow-file formats…), then runs a dictionary attack against common passwords |
| **Cipher lab** | ROT13, Caesar, Caesar brute-force with English frequency scoring, Vigenère, Base64, Hex, Binary, Morse |
| **JWT auditor** | Decodes JSON Web Tokens and flags `alg: none`, missing/expired `exp`, sensitive claims, and more |

## Try it

```text
root@cyberkit:~$ hashid 5f4dcc3b5aa765d61d8327deb882cf99
  → MD5
  → NTLM (Windows)
  → MD4
[CRACKED] MD5("password")
```

Paste `Uryyb, unpxre!` into the cipher lab and hit **ROT13**, or try the Caesar brute-forcer.

## Run it

- **Locally:** download the repo and double-click `index.html`.
- **Online:** https://aziz4rehman-hue.github.io/cyberkit/ (hosted on GitHub Pages)

## What I learned

- Why fast hashes (MD5/SHA-1) are terrible for storing passwords, and why bcrypt/Argon2 exist
- How password entropy and crack-time estimates work
- How classical ciphers work and how frequency analysis breaks them
- Common JWT misconfigurations
- How much your browser reveals for fingerprinting

## Disclaimer

Built for **learning and defense**. The `hack` command is a pure animation and does nothing. Only test systems you own or have permission to test. To practice legally, try [picoCTF](https://picoctf.org), [TryHackMe](https://tryhackme.com), [Hack The Box](https://hackthebox.com) or [OverTheWire](https://overthewire.org).

## License

MIT
