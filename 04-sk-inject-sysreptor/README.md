# sk_inject — Injecteur de rapport SysReptor

**Crée un rapport SysReptor directement à partir d'un fichier `.txt`
formaté (blocs `=== ... ===`).**

## Workflow

1. Notes brutes collées dans Claude (projet « reporting »)
2. Claude génère un rapport formaté avec des blocs `=== ... ===`
3. Sauvegarde de la réponse dans un `.txt`
4. `python3 sk_injectfinal.py rapport.txt` → rapport créé dans SysReptor

## Variantes

- `sk_inject.py`     — version de base
- `sk_injectfinal.py` — version finale : nettoyage déterministe des
  séparateurs LLM, **redaction des hashs et secrets à motif
  reconnaissable** (à privilégier publiquement)

## Usage

```bash
export SYSREPTOR_TOKEN=ton_token
python3 sk_injectfinal.py rapport_formate.txt
```

## Dépendances

- Python 3
- `requests`  (`pip install -r requirements.txt`)
- SysReptor accessible (URL configurable, `http://127.0.0.1:8000` par défaut)

## Sécurité

- Le token est lu depuis l'environnement — **ne jamais committer de `.env`**.
- `SYSREPTOR_URL` et `DESIGN_ID` sont configurables en haut du script.

## Licence

MIT