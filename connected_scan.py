import subprocess as sp # interact with the OS    
import nmap as nmap

check_cmd = 'python3 -c "import nmap; print(nmap.__version__)"'
result = sp.run(check_cmd, shell=True, capture_output=True, text=True)

if result.returncode != 0:  # non-zero means import failed
    print("[-] python-nmap is not installed")
    print("[+] Installing now...")
    sp.run("sudo apt update", shell=True)
    sp.run("sudo apt install -y python3-pip", shell=True)
    sp.run("pip3 install python-nmap", shell=True)
else:
    print(f"[+] python-nmap already installed (version {result.stdout.strip()})")



class Recon:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        
    def connection_info(self):
        print("Connected network info")
        sp.run(["ip", "a"], check=False)
        sp.run(["iwconfig"], check=False)

    def find_live_hosts(self):
        """
        General format for nmap:
        nmap[scan type][Options][target specification]
        """
        print("What network interface do you want to scan? \n1. eth0 \n2. wlan0" )
        choice = input("Enter your choice: ")
        if choice == "1":
            interface = "eth0"
        elif choice == "2":
            interface = "wlan0"
        else:
            print("Invalid choice. Please enter 1 or 2.")
            return[]
        
        args = f"-e {interface} -sS -sV --top-ports 200 -O --osscan-limit --osscan-guess -n -T4 -PR" # arguments logic
        

        input_ip = input("CIDR (e.g., 192.168.68.0/22): ").strip()
        if "/" not in input_ip:
            print("[!] Please enter CIDR (e.g., 192.168.68.0/22)")
            return []

        print("[!] This scan requires root privileges. If not in root terminal, please exit and run as root.")
        print("Proceed to scan? \n1. Yes \n2. No (exit program!)")
        choice = input("Enter your choice: ").strip()
        if choice == "2":
            print("[+] Exiting program.")
            exit()
        else:
        
            print(f"[+] Scanning {input_ip} on {interface} for live hosts...")
            print("Focused-OS SYN scan")

            self.scanner.scan(hosts = input_ip, arguments = args) #scanning

            host_count = 0
            live_host = []

            for host in self.scanner.all_hosts():
                if self.scanner[host].state() == "up": # if this is a live host
                    host_count += 1

                    # Basic info
                    ip = self.scanner[host].get("addresses", {}).get("ipv4", host)
                    mac = self.scanner[host].get("addresses", {}).get("mac", "")
                    vendor_map = self.scanner[host].get("vendor", {})
                    vendor = next(iter(vendor_map.values()), "") if vendor_map else ""
                            
                            
                    #Ports
                    open_ports = []
                    for protocol in self.scanner[host].all_protocols():
                        for port, port_data in self.scanner[host][protocol].items():
                            if port_data.get('state') == 'open':
                                service = port_data.get('name', '')
                                version = port_data.get('version', '')
                                product = port_data.get('product', '')
                                extrainfo = port_data.get('extrainfo', '')

                                # Build a readable string
                                svc_info_parts = [service, product, version, extrainfo]
                                svc_info = ' '.join(part for part in svc_info_parts if part).strip()

                                if svc_info:
                                    open_ports.append(f"{port}/{protocol} ({svc_info})")
                                else:
                                    open_ports.append(f"{port}/{protocol}")

                    #OS
                    os_name = ""
                    osmatches = self.scanner[host].get("osmatch", [])
                    if osmatches:
                        os_name = osmatches[0].get("name", "")


                    live_host.append({
                        "IP": ip, 
                        "MAC": mac, 
                        "Opening_port": open_ports,
                        "OS": os_name,
                        "Vendor": vendor        
                        })        
                        
            print(f"[+] Found {host_count} live hosts. Results saved to csv file.")
            return live_host
    
    def write_scan_results(self, results, csv_file="scan_results.csv"):
        with open(csv_file, "w", encoding="utf-8") as f_csv:
            f_csv.write("ip,mac,vendor,open_ports,os\n")
            for entry in results:
                # Join ports with semicolon to avoid splitting across columns if service names contain commas
                ports_str = "; ".join(entry.get("Opening_port", []))
                
                # Escape any commas in vendor/OS fields just in case
                ip = entry.get("IP", "")
                mac = entry.get("MAC", "")
                vendor = entry.get("Vendor", "").replace(",", " ")
                os_name = entry.get("OS", "").replace(",", " ")

                f_csv.write(f"{ip},{mac},{vendor},{ports_str},{os_name}\n")

        print(f"[+] Wrote {len(results)} hosts to {csv_file}")


if __name__ == "__main__":
    r = Recon()
    while True:
        print("Start scanning for target? \n1. Yes \n2. No (exit program!)")
        choice = input("Enter your choice: ").strip()
        
        if choice == "1":
            r.connection_info()
            results = r.find_live_hosts()  # returns list[dict]
            if results:
                r.write_scan_results(results)  # consumes that list
            else:
                print("[!] No results found.")
        elif choice == "2":
            print("[+] Exiting program.")
            break
        else:
            print("[!] Invalid choice, please enter 1 or 2.")

        
        
    

