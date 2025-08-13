# DISCLAIMER:
# This script is for educational and authorized penetration testing purposes only.
# Use only on networks you own or have explicit permission to test.
# Unauthorized use may violate local, state, or federal laws.
# The author is not responsible for misuse.

#Requirements:
#hashcat.exe (https://hashcat.net/hashcat/)
#h.22000 file (get from capture_handshake.py)
#wordlist (after using merge_list.py)
#Decent GPU or CPU (preferably NVIDIA)

import tkinter as tk
from tkinter import filedialog
import subprocess as sp
import pathlib, time, sys

root = tk.Tk(); root.withdraw()

#Choose the hashcat.exe file
print("Select your Hashcat.exe file...")
hashcat_path = filedialog.askopenfilename(title="Select hashcat.exe",
    filetypes=[("Hashcat Executable","hashcat.exe"), ("Executable Files","*.exe"), ("All Files","*.*")])
if not hashcat_path: sys.exit("No file selected.")

hashcat_dir = pathlib.Path(hashcat_path).parent

#Choose the h.22000 file, this file is crucial for cracking, it gotta be converted from .cap file
print("Select your .22000 or .hccapx file...")
capture_path = filedialog.askopenfilename(title="Select capture file",
    filetypes=[("Capture Files","*.22000 *.hccapx")])
if not capture_path: sys.exit("No capture selected.")

#Choose the word/password list 
print("Select your wordlist (e.g., rockyou.txt)...")
wordlist_path = filedialog.askopenfilename(title="Select wordlist",
    filetypes=[("Wordlist Files","*.txt *.lst"), ("All Files","*.*")])
if not wordlist_path: sys.exit("No wordlist selected.")

#Just a helper method to check the availability of CUDA-enabled GPU for NVIDIA
def cuda_available():
    out = sp.run([hashcat_path, "-I"], cwd=str(hashcat_dir),
                 capture_output=True, text=True).stdout
    return ("CUDA API" in out) or ("CUDA.Version" in out)

# "cuda" = NVIDIA only (smoother UI), "opencl" = NVIDIA + Intel iGPU (slightly faster if you have an iGPU, but more heat though)
# "auto" = prefer CUDA if available, else OpenCL
backend_choice = "opencl"   # change to "cuda" if you prefer CUDA only
if backend_choice == "auto":
    backend_choice = "cuda" if cuda_available() else "opencl"

ignore_flags = []
if backend_choice == "cuda":
    ignore_flags = ["--backend-ignore-opencl"]
elif backend_choice == "opencl":
    ignore_flags = ["--backend-ignore-cuda"]

# mode for encryption type, 22000 is the modern one, 2500 is legacy
mode = "22000" if capture_path.lower().endswith(".22000") else "2500"

# This is where the cracked keys will be saved
outfile_path = filedialog.asksaveasfilename(
    title="Where should I save cracked keys?",
    defaultextension=".txt", initialfile="found.txt",
    filetypes=[("Text files","*.txt"), ("All files","*.*")]
) or str(pathlib.Path(capture_path).with_suffix(".found.txt"))
pathlib.Path(outfile_path).parent.mkdir(parents=True, exist_ok=True)
open(outfile_path, "a", encoding="utf-8").close()

# select the rule file
print("Select your hashcat rule file...")
rule_file = filedialog.askopenfilename(
    title="Select hashcat rule file",
    filetypes=[("Hashcat Rule Files", "*.rule")]
)

# If no rule file manually selected, check the defaults
if not rule_file:
    for rule in ("best66.rule", "rockyou-30000.rule"): #these 2 are the default just in case no rule is selected
        p = hashcat_dir / "rules" / rule
        if p.exists():
            rule_file = str(p)
            break

# give the session time
stamp = time.strftime("%m%d_%H%M%S")
session = f"wifi_{backend_choice}_{stamp}"

# This is the main argument logic for hashcat to start cracking
args = [
    hashcat_path,
    *ignore_flags,                 # e.g., ["--backend-ignore-opencl"] or ["--backend-ignore-cuda"]
    "-m", mode,                    # "22000" or "2500" mode
    capture_path,
    wordlist_path,
    "-w", "3",
    "--status", "--status-timer", "10",
    "--session", session,
    "--outfile", outfile_path, "--outfile-format", "2",
]

if rule_file:
    args += ["-r", str(rule_file)]

sp.run(args, cwd=str(hashcat_dir))

print(f"[i] Backend: {backend_choice} | Mode: {mode}")
print(f"[i] Rule: {rule_file.name if rule_file else 'none'}")
print(f"[i] Outfile: {outfile_path}")
sp.run(args, cwd=str(hashcat_dir))
