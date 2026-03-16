import bcrypt
import os
from datetime import datetime
import time

from encryption import encrypt_password, decrypt_password
from database import add_entry, get_entries, delete_entry
from password_checker import check_strength, generate_password
from password_checker import check_breach

import os

# Get the directory where main.py is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Full path to logs/login_logs.txt
LOG_FILE = os.path.join(BASE_DIR, "logs", "login_logs.txt")

# Create the logs folder if missing
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Create the file if missing
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        f.write("SecureVault log started\n")


def log_event(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {message}\n")

def setup_master_password():

    password = input("Create master password: ")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    with open("master.hash", "wb") as f:
        f.write(hashed)


def verify_master_password():
    if not os.path.exists("master.hash"):
        setup_master_password()
        log_event("Master password created")  # <-- log vault setup

    with open("master.hash", "rb") as f:
        stored_hash = f.read()

    attempts = 0

    while attempts < 3:

        password = input("Enter master password: ")

        if bcrypt.checkpw(password.encode(), stored_hash):
            log_event("Successful login")
            return True

        else:
            attempts += 1
            log_event("Failed login attempt")
            print("Wrong password")

    if attempts == 3:
        print("Too many attempts. Locked for 120 seconds.")
        log_event("System locked due to brute-force attempts")
        time.sleep(120)


def menu():

    while True:

        print("\nSecureVault")
        print("1 Add password")
        print("2 View passwords")
        print("3 Generate strong password")
        print("4 Check password strength")
        print("5 Delete password")
        print("6 Exit")
        print("7 Security audit")

        choice = input("Choose option: ")

        if choice == "1":

            site = input("Website: ")
            username = input("Username: ")
            password = input("Password: ")
            breach_count = check_breach(password)
            if breach_count > 0:
                print("WARNING: This password appeared in data breaches", breach_count, "times")
            strength = check_strength(password)
            print("Password strength:", strength)

            add_entry(site, username, password, encrypt_password)
            print("Password saved")


        elif choice == "2":

            entries = get_entries(decrypt_password)

            for site in entries:
                print("\nSite:", site)
                print("Username:", entries[site]["username"])
                print("Password:", entries[site]["password"])

        elif choice == "3":

            print("Generated password:", generate_password())

        elif choice == "4":

            password = input("Enter password: ")
            print("Strength:", check_strength(password))


        elif choice == "5":

            site = input("Site to delete: ")

            if delete_entry(site):
                print("Deleted")
            else:
                print("Site not found")

        elif choice == "6":
            break

        elif choice == "7":

            from database import audit_vault

            reused = audit_vault(decrypt_password)

            if reused:
                print("Reused passwords found on:")
                for site in reused:
                    print(site)
            else:
                print("No reused passwords detected")


        else:
            print("Invalid option")


if verify_master_password():
    menu()
