# DISCLAIMER:
# This script is for educational and authorized penetration testing purposes only.
# Use only on networks you own or have explicit permission to test.
# Unauthorized use may violate local, state, or federal laws.
# The author is not responsible for misuse.

#Requirements:
#Do research regarding the target, create a seed.txt file of the target
#Consult for some leaked password lists: 
    # https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm
    # https://weakpass.com/
# Then merge them using this script

import tkinter as tk
from tkinter import filedialog
import glob
import os
import sys

# hide tkinter root
root = tk.Tk()
root.withdraw()

# Select input folder containing .txt files
input_folder = filedialog.askdirectory(title="Select folder containing word list files")
if not input_folder:
    print("No input folder selected. Exiting...")
    sys.exit(0)

# Select output file (ask for full path + name)
output_file = filedialog.asksaveasfilename(
    title="Save merged wordlist as...",
    defaultextension=".txt",
    filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
)
if not output_file:
    print("No output file selected. Exiting...")
    sys.exit(0)

# Collect all .txt files in the folder
files = glob.glob(os.path.join(input_folder, "*.txt"))
if not files:
    print("No .txt files found in the selected folder. Exiting...")
    sys.exit(0)

# Priority: seed* -> cupp* -> others
def priority_key(path):
    name = os.path.basename(path).lower()
    if name.startswith("seed"):
        return (0, name)
    if name.startswith("cupp") or "cupp" in name:
        return (1, name)
    return (2, name)

files.sort(key=priority_key)

MIN_LEN, MAX_LEN = 8, 63  # WPA(2/3)-PSK valid pasword lengths

seen = {}  # preserves insertion order; use as an ordered set

total_read = total_kept = too_short = too_long = dupes = 0

for fp in files:
    with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            total_read += 1
            w = line.strip()  # keep it simple per your preference
            if not w:
                continue
            L = len(w)
            if L < MIN_LEN:
                too_short += 1
                continue
            if L > MAX_LEN:
                too_long += 1
                continue
            if w in seen:
                dupes += 1
                continue
            seen[w] = None
            total_kept += 1

with open(output_file, "w", encoding="utf-8") as out:
    for w in seen.keys():          # write in first-seen (priority) order
        out.write(w + "\n")

print(f"Merged {len(files)} files into: {output_file}")
print(f"Total lines read: {total_read}")
print(f"Kept (unique, {MIN_LEN}-{MAX_LEN} chars): {total_kept}")
print(f"Dropped too short: {too_short} | too long: {too_long} | duplicates: {dupes}")
