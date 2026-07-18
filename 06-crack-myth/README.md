# crack_myth.py

**Cracker par dictionnaire pour hashs PBKDF2-HMAC-SHA256.**

Outil éducatif / CTF : itère une wordlist et compare le hash dérivé à une
cible fournie en base64.

## Usage

```bash
python3 crack_myth.py <hash_b64> [wordlist] [iterations] [dklen]
python3 crack_myth.py --help
```

## Exemple

```bash
python3 crack_myth.py "u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==" \
    /usr/share/wordlists/rockyou.txt
```

## Paramètres

| Position | Rôle        | Défaut                          |
|----------|-------------|---------------------------------|
| 1        | hash b64    | (obligatoire)                   |
| 2        | wordlist    | `/usr/share/wordlists/rockyou.txt` |
| 3        | iterations  | `1000`                          |
| 4        | dklen       | `40`                            |

> Le salt est vide par défaut, modifie la variable `salt` dans le code
> si ton schéma en utilise un.

## Dépendances

- Python 3 (stdlib uniquement : `hashlib`, `base64`, `sys`)

## Licence

MIT, usage éducatif / CTF