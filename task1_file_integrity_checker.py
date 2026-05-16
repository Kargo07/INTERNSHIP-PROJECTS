"""
============================================================
CODTECH INTERNSHIP - TASK 1
FILE INTEGRITY CHECKER
============================================================
Description : Monitor changes in files by calculating and
              comparing hash values using hashlib.
Author      : Intern
Libraries   : hashlib, os, json, datetime
============================================================
"""

import hashlib
import os
import json
from datetime import datetime


# ─────────────────────────────────────────────
# 1. Calculate hash of a single file
# ─────────────────────────────────────────────
def calculate_hash(filepath, algorithm="sha256"):
    """
    Calculate the hash of a file using the specified algorithm.
    Supported: md5, sha1, sha256 (default), sha512
    """
    hash_func = hashlib.new(algorithm)

    try:
        with open(filepath, "rb") as f:
            # Read file in chunks to handle large files efficiently
            while chunk := f.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        return None
    except PermissionError:
        print(f"[ERROR] Permission denied: {filepath}")
        return None


# ─────────────────────────────────────────────
# 2. Scan a directory and collect all file hashes
# ─────────────────────────────────────────────
def scan_directory(directory, algorithm="sha256"):
    """
    Scan all files in a directory (recursively) and return
    a dict mapping filepath -> hash value.
    """
    file_hashes = {}

    if not os.path.isdir(directory):
        print(f"[ERROR] Directory does not exist: {directory}")
        return file_hashes

    for root, dirs, files in os.walk(directory):
        # Skip hidden directories (optional)
        dirs[:] = [d for d in dirs if not d.startswith(".")]

        for filename in files:
            filepath = os.path.join(root, filename)
            file_hash = calculate_hash(filepath, algorithm)
            if file_hash:
                # Store relative path for portability
                rel_path = os.path.relpath(filepath, directory)
                file_hashes[rel_path] = {
                    "hash": file_hash,
                    "algorithm": algorithm,
                    "size_bytes": os.path.getsize(filepath),
                    "last_modified": datetime.fromtimestamp(
                        os.path.getmtime(filepath)
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                }

    return file_hashes


# ─────────────────────────────────────────────
# 3. Save baseline snapshot to JSON
# ─────────────────────────────────────────────
def save_baseline(file_hashes, baseline_file="baseline.json"):
    """
    Save the current hash snapshot as a baseline for future comparison.
    """
    snapshot = {
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_files": len(file_hashes),
        "files": file_hashes,
    }

    with open(baseline_file, "w") as f:
        json.dump(snapshot, f, indent=4)

    print(f"\n[✔] Baseline saved → {baseline_file}")
    print(f"    Total files recorded: {len(file_hashes)}")


# ─────────────────────────────────────────────
# 4. Load existing baseline from JSON
# ─────────────────────────────────────────────
def load_baseline(baseline_file="baseline.json"):
    """
    Load a previously saved baseline snapshot.
    """
    if not os.path.exists(baseline_file):
        print(f"[ERROR] Baseline file not found: {baseline_file}")
        return None

    with open(baseline_file, "r") as f:
        snapshot = json.load(f)

    print(f"[INFO] Baseline loaded (created: {snapshot['created_at']})")
    print(f"[INFO] Baseline contains {snapshot['total_files']} file(s).")
    return snapshot["files"]


# ─────────────────────────────────────────────
# 5. Compare current state with baseline
# ─────────────────────────────────────────────
def compare_with_baseline(current_hashes, baseline_hashes):
    """
    Compare current file hashes with baseline and report:
    - Modified files (hash changed)
    - New files (not in baseline)
    - Deleted files (in baseline but missing now)
    """
    print("\n" + "=" * 60)
    print("         FILE INTEGRITY COMPARISON REPORT")
    print("=" * 60)

    modified = []
    new_files = []
    deleted = []
    unchanged = []

    # Check for modified and new files
    for filepath, info in current_hashes.items():
        if filepath in baseline_hashes:
            if info["hash"] != baseline_hashes[filepath]["hash"]:
                modified.append(filepath)
            else:
                unchanged.append(filepath)
        else:
            new_files.append(filepath)

    # Check for deleted files
    for filepath in baseline_hashes:
        if filepath not in current_hashes:
            deleted.append(filepath)

    # ── Print Results ──
    if modified:
        print(f"\n[⚠ MODIFIED] {len(modified)} file(s) changed:")
        for f in modified:
            print(f"    → {f}")
            print(f"       Old hash: {baseline_hashes[f]['hash']}")
            print(f"       New hash: {current_hashes[f]['hash']}")

    if new_files:
        print(f"\n[+ NEW] {len(new_files)} new file(s) found:")
        for f in new_files:
            print(f"    + {f}")

    if deleted:
        print(f"\n[- DELETED] {len(deleted)} file(s) removed:")
        for f in deleted:
            print(f"    - {f}")

    if unchanged:
        print(f"\n[✔ OK] {len(unchanged)} file(s) are unchanged.")

    if not modified and not new_files and not deleted:
        print("\n[✔] All files are INTACT. No changes detected.")

    print("\n" + "=" * 60)

    # Summary
    print("SUMMARY:")
    print(f"  Unchanged : {len(unchanged)}")
    print(f"  Modified  : {len(modified)}")
    print(f"  New       : {len(new_files)}")
    print(f"  Deleted   : {len(deleted)}")
    print("=" * 60)

    return {
        "modified": modified,
        "new": new_files,
        "deleted": deleted,
        "unchanged": unchanged,
    }


# ─────────────────────────────────────────────
# 6. Monitor a single file for changes
# ─────────────────────────────────────────────
def check_single_file(filepath, expected_hash, algorithm="sha256"):
    """
    Verify integrity of a single file against a known hash value.
    """
    print(f"\n[INFO] Checking file: {filepath}")
    current_hash = calculate_hash(filepath, algorithm)

    if current_hash is None:
        return

    print(f"  Expected : {expected_hash}")
    print(f"  Current  : {current_hash}")

    if current_hash == expected_hash:
        print(f"  Status   : ✔ INTACT — File has not been tampered.")
    else:
        print(f"  Status   : ✘ MODIFIED — File integrity compromised!")


# ─────────────────────────────────────────────
# 7. Main Menu
# ─────────────────────────────────────────────
def main():
    print("=" * 60)
    print("     CODTECH INTERNSHIP - FILE INTEGRITY CHECKER")
    print("=" * 60)

    while True:
        print("\nOptions:")
        print("  1. Create Baseline (scan directory)")
        print("  2. Check Integrity (compare with baseline)")
        print("  3. Check Single File")
        print("  4. Exit")

        choice = input("\nEnter choice [1-4]: ").strip()

        if choice == "1":
            directory = input("Enter directory path to scan: ").strip()
            algo = input("Hash algorithm [sha256/md5/sha1/sha512] (default: sha256): ").strip()
            algo = algo if algo in ["md5", "sha1", "sha256", "sha512"] else "sha256"
            baseline_file = input("Save baseline as (default: baseline.json): ").strip()
            baseline_file = baseline_file if baseline_file else "baseline.json"

            print(f"\n[INFO] Scanning '{directory}' using {algo.upper()}...")
            hashes = scan_directory(directory, algo)

            if hashes:
                save_baseline(hashes, baseline_file)
            else:
                print("[WARN] No files found to hash.")

        elif choice == "2":
            baseline_file = input("Baseline file path (default: baseline.json): ").strip()
            baseline_file = baseline_file if baseline_file else "baseline.json"
            directory = input("Directory to scan now: ").strip()
            algo = input("Hash algorithm [sha256/md5/sha1/sha512] (default: sha256): ").strip()
            algo = algo if algo in ["md5", "sha1", "sha256", "sha512"] else "sha256"

            baseline_hashes = load_baseline(baseline_file)
            if baseline_hashes is None:
                continue

            print(f"\n[INFO] Scanning '{directory}'...")
            current_hashes = scan_directory(directory, algo)

            if current_hashes:
                compare_with_baseline(current_hashes, baseline_hashes)
            else:
                print("[WARN] No files found in the directory.")

        elif choice == "3":
            filepath = input("File path: ").strip()
            expected = input("Expected hash value: ").strip()
            algo = input("Algorithm used [sha256/md5/sha1] (default: sha256): ").strip()
            algo = algo if algo in ["md5", "sha1", "sha256", "sha512"] else "sha256"
            check_single_file(filepath, expected, algo)

        elif choice == "4":
            print("\n[BYE] Exiting File Integrity Checker. Stay secure!")
            break

        else:
            print("[ERROR] Invalid choice. Please enter 1-4.")


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    main()
       
