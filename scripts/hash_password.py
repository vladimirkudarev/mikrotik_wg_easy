#!/usr/bin/env python3
import getpass
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "mikrotik_wg_easy"))
from app import hash_password  # noqa: E402


def main():
    password = getpass.getpass("Password: ")
    repeat = getpass.getpass("Repeat: ")
    if password != repeat:
        raise SystemExit("Passwords do not match")
    print(hash_password(password))


if __name__ == "__main__":
    main()
