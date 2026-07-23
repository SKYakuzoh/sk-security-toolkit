#!/usr/bin/env python3
"""
crack_myth.py - Cracker PBKDF2-HMAC-SHA256 (1000 itérations, dklen=40) contre une wordlist.

Usage:
    python3 crack_myth.py <hash_b64> [wordlist] [iterations] [dklen]
    python3 crack_myth.py --help

Exemple:
    python3 crack_myth.py "u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==" /usr/share/wordlists/rockyou.txt

Le hash cible doit être fourni en base64 (salt vide par défaut ; adapte si besoin).
"""
import hashlib
import base64
import sys

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    target_b64 = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_WORDLIST
    iterations = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
    dklen = int(sys.argv[4]) if len(sys.argv) > 4 else 40

    try:
        target_bytes = base64.b64decode(target_b64)
    except Exception as e:
        print(f"[-] Hash base64 invalide : {e}")
        sys.exit(2)

    salt = b""  # salt vide d'origine ; modifie si ton schéma utilise un salt

    try:
        f = open(wordlist, "rb")
    except FileNotFoundError:
        print(f"[-] Wordlist introuvable : {wordlist}")
        sys.exit(2)

    with f:
        for i, line in enumerate(f):
            word = line.strip()
            if not word:
                continue
            h = hashlib.pbkdf2_hmac("sha256", word, salt, iterations, dklen=dklen)
            if h == target_bytes:
                print(f"[+] FOUND: {word.decode(errors='ignore')}")
                sys.exit(0)
            if i % 100000 == 0:
                print(f"[*] {i} tested...", flush=True)

    print("[-] Not found")


if __name__ == "__main__":
    main()