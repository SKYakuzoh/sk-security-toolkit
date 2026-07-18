#!/usr/bin/env python3
"""
SK Security — SysReptor Injector
Usage: python3 sk_inject.py rapport_formate.txt
Requires: SYSREPTOR_TOKEN dans l'environnement ou .env

Workflow :
  1. Colle tes notes brutes dans Claude.ai (projet SK Security Reporting)
  2. Claude génère le rapport formaté avec les blocs === ... ===
  3. Sauvegarde la réponse dans un fichier .txt
  4. Lance ce script → rapport créé directement dans SysReptor
"""

import os
import sys
import json
import re
import requests
from datetime import date

# ─── CONFIG ───────────────────────────────────────────────────────────────────
SYSREPTOR_URL   = "http://127.0.0.1:8000"
DESIGN_ID       = "11071dd1-d42f-4a1c-a1ac-81a6a2d69639"
SYSREPTOR_TOKEN = os.environ.get("SYSREPTOR_TOKEN", "")

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def sysreptor_headers():
    return {
        "Authorization": f"Bearer {SYSREPTOR_TOKEN}",
        "Content-Type": "application/json",
        "X-CSRFToken": ""
    }


def parse_blocks(text: str) -> dict:
    """Parse les blocs === NOM === du fichier formaté."""
    pattern = r"===\s*(.+?)\s*===\s*\n(.*?)(?====|\Z)"
    matches = re.findall(pattern, text, re.DOTALL)
    blocks = {}
    for name, content in matches:
        blocks[name.strip()] = content.strip()
    return blocks


def parse_info(content: str) -> dict:
    """Parse les infos générales clé: valeur."""
    info = {}
    for line in content.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            info[key.strip()] = val.strip()
    return info


def parse_finding(content: str) -> dict:
    """Parse un bloc finding en dictionnaire."""
    finding = {}
    fields = [
        "Titre", "CWE", "CVSS Score", "CVSS Vecteur", "Actif",
        "Description", "Chaîne d'exploitation", "Impact",
        "Recommandation", "Références"
    ]
    for i, field in enumerate(fields):
        next_field = fields[i + 1] if i + 1 < len(fields) else None
        if next_field:
            pattern = rf"{re.escape(field)}:\s*(.*?)(?={re.escape(next_field)}:|\Z)"
        else:
            pattern = rf"{re.escape(field)}:\s*(.*?)$"
        m = re.search(pattern, content, re.DOTALL)
        finding[field] = m.group(1).strip() if m else ""
    return finding


def create_project(client_name: str, ref: str) -> str:
    payload = {
        "name": f"{client_name} — {ref}",
        "project_type": DESIGN_ID,
        "tags": ["SK Security"]
    }
    r = requests.post(
        f"{SYSREPTOR_URL}/api/v1/pentestprojects/",
        headers=sysreptor_headers(),
        json=payload
    )
    if not r.ok:
        print(f"[!] Erreur création projet : {r.status_code} — {r.text}")
        r.raise_for_status()
    project_id = r.json()["id"]
    print(f"[+] Projet créé : {project_id}")
    return project_id


def update_section(project_id: str, section_id: str, data: dict):
    """Injecter les données dans une section spécifique de SysReptor."""
    r = requests.patch(
        f"{SYSREPTOR_URL}/api/v1/pentestprojects/{project_id}/sections/{section_id}/",
        headers=sysreptor_headers(),
        json={"data": data}
    )
    if not r.ok:
        print(f"[!] Erreur section {section_id} : {r.status_code} — {r.text}")
    else:
        print(f"[+] Section '{section_id}' injectée")


def create_finding(project_id: str, finding_data: dict, finding_id: str):
    cvss_vector = finding_data.get("CVSS Vecteur", "n/a")

    # Références — une par ligne commençant par http
    refs_raw = finding_data.get("Références", "")
    refs = [r.strip() for r in refs_raw.splitlines() if r.strip().startswith("http")]

    payload = {
        "data": {
            "title":              finding_data.get("Titre", "TODO"),
            "cvss":               cvss_vector,
            "finding_id":         finding_id,
            "cwe_cve":            finding_data.get("CWE", "CWE-TODO"),
            "affected_asset":     finding_data.get("Actif", "TODO"),
            "description":        finding_data.get("Description", "TODO"),
            "exploitation_chain": finding_data.get("Chaîne d'exploitation", "TODO"),
            "impact":             finding_data.get("Impact", "TODO"),
            "recommendation":     finding_data.get("Recommandation", "TODO"),
            "references":         refs
        }
    }
    r = requests.post(
        f"{SYSREPTOR_URL}/api/v1/pentestprojects/{project_id}/findings/",
        headers=sysreptor_headers(),
        json=payload
    )
    if not r.ok:
        print(f"[!] Erreur création finding : {r.status_code} — {r.text}")
        r.raise_for_status()
    fid = r.json()["id"]
    print(f"[+] Finding créé : {finding_data.get('Titre', 'TODO')} ({fid})")
    return fid


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 sk_inject.py rapport_formate.txt")
        sys.exit(1)

    if not SYSREPTOR_TOKEN:
        print("Erreur : SYSREPTOR_TOKEN manquant.")
        print("Lance : export SYSREPTOR_TOKEN=ton_token")
        sys.exit(1)

    with open(sys.argv[1], "r", encoding="utf-8") as f:
        text = f.read()

    print("[*] Parsing du fichier formaté...")
    blocks = parse_blocks(text)

    if not blocks:
        print("[!] Aucun bloc détecté. Vérifie que le fichier contient des blocs === NOM ===")
        sys.exit(1)

    # Infos générales
    info        = parse_info(blocks.get("INFORMATIONS GÉNÉRALES", ""))
    client_name = info.get("Nom du client", "Client")
    ref         = info.get("Référence", "SKS-2026-001")
    audit_type  = info.get("Type d'audit", "Boîte grise")
    period      = info.get("Période", "TODO")
    access      = info.get("Accès fournis", "Compte de domaine (credentials fournis de manière sécurisée)")
    risk_level  = info.get("Niveau de risque global", "CRITIQUE").upper()

    print(f"[*] Client : {client_name} | Ref : {ref} | Risque : {risk_level}")

    # Création projet
    project_id = create_project(client_name, ref)

    # Injection par section selon la structure SysReptor
    update_section(project_id, "general", {
        "title":             f"{client_name} — {ref}",
        "client_name":       client_name,
        "ref":               ref,
        "version":           "1.0",
        "date":              date.today().isoformat(),
        "audit_type":        audit_type,
        "risk_level":        risk_level.capitalize(),
        "period":            period,
        "access":            access,
        "executive_summary": blocks.get("report.executive_summary", "TODO"),
    })
    update_section(project_id, "contacts", {
        "client_contacts": blocks.get("CONTACTS CLIENT", "TODO"),
    })
    update_section(project_id, "scope_section", {
        "scope":      blocks.get("report.scope", "TODO"),
        "tools_used": blocks.get("report.tools", "TODO"),
    })
    update_section(project_id, "content", {
        "introduction":   blocks.get("report.introduction", "TODO"),
        "findings_intro": blocks.get("report.findings_intro", "Les scores CVSS présentés ci-après évaluent chaque vulnérabilité en isolation."),
        "conclusion":     blocks.get("report.conclusion", "TODO"),
    })

    # Findings
    finding_blocks = {k: v for k, v in blocks.items() if k.startswith("FINDING")}
    print(f"[*] {len(finding_blocks)} finding(s) détecté(s)...")

    for i, (fname, fcontent) in enumerate(finding_blocks.items(), 1):
        # Extraire l'ID depuis le nom du bloc (ex: "FINDING SKS-2026-001")
        id_match = re.search(r"SKS-\d{4}-\d+", fname)
        finding_id = id_match.group(0) if id_match else f"SKS-2026-{i:03d}"
        finding = parse_finding(fcontent)
        create_finding(project_id, finding, finding_id)

    print(f"\n[+] Rapport injecté avec succès !")
    print(f"[+] Ouvre SysReptor : {SYSREPTOR_URL}/projects/{project_id}/")


if __name__ == "__main__":
    main()
