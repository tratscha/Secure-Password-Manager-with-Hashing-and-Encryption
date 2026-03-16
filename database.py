import json
import os

VAULT_FILE = "vault.json"

def load_vault():
    if not os.path.exists(VAULT_FILE):
        return {}

    with open(VAULT_FILE, "r") as f:
        return json.load(f)

def save_vault(vault):
    with open(VAULT_FILE, "w") as f:
        json.dump(vault, f, indent=4)

def add_entry(site, username, password, encrypt_func):
    vault = load_vault()

    vault[site] = {
        "username": username,
        "password": encrypt_func(password)
    }

    save_vault(vault)

def get_entries(decrypt_func):
    vault = load_vault()
    entries = {}

    for site in vault:
        username = vault[site]["username"]
        encrypted = vault[site]["password"]

        entries[site] = {
            "username": username,
            "password": decrypt_func(encrypted)
        }

    return entries

def delete_entry(site):
    vault = load_vault()

    if site in vault:
        del vault[site]
        save_vault(vault)
        return True

    return False
def audit_vault(decrypt_func):

    vault = load_vault()

    passwords = {}
    reused = []

    for site in vault:

        encrypted = vault[site]["password"]
        password = decrypt_func(encrypted)

        if password in passwords:
            reused.append(site)
        else:
            passwords[password] = site

    return reused
