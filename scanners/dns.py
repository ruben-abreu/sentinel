import dns.resolver
import urllib.request
import json
import os

VT_API_KEY = os.getenv("VT_API_KEY")

def run(target, target_type):
    if target_type == "Domain":
        print(f"\n[*] Mapping Active Records to the Domain {target}...")
        try:
            answers = dns.resolver.resolve(target, 'A')
            print(f"\n[+] Active DNS Records Found for {target}:")
            for rdata in answers:
                print(f"    -> IP Address (A Record): \033[1m{rdata.to_text()}\033[0m")
        except Exception as e:
            print(f"[!] Error resolving domain: {e}")

    elif target_type == "IP Address":
        print(f"\n[*] Starting Passive DNS (pDNS Graph) validation for IP: {target}...")
        raw_domains = set()

        if VT_API_KEY and VT_API_KEY != "":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}/resolutions"
            req = urllib.request.Request(url)
            req.add_header("x-apikey", VT_API_KEY)
            req.add_header("accept", "application/json")
            
            try:
                with urllib.request.urlopen(req, timeout=7) as response:
                    data = json.loads(response.read().decode('utf-8'))
                    for resolution in data.get("data", []):
                        host_name = resolution.get("attributes", {}).get("host_name")
                        if host_name:
                            raw_domains.add(host_name.rstrip('.'))
            except Exception as e:
                print(f"[!] VirusTotal pDNS query failed: {e}")
                return
        else:
            print("[!] VirusTotal API key not found.\n"
    "    Create a .env file in the project root containing:\n"
    "    VT_API_KEY=your_api_key")
            return

        filtered_domains = set()
        
        # Palavras-chave típicas de circuitos e sub-redes de operadoras de internet
        isp_keywords = [
            "telecom", "belgacom", "isp", "adsl", "dynamic", "static", 
            "pool", "client", "cable", "vocalone", "fibra", "ftth", "dialup"
        ]
        
        ip_dashed = target.replace('.', '-')
        
        for host in raw_domains:
            host_lower = host.lower()
            
            if any(keyword in host_lower for keyword in isp_keywords):
                continue
                
            if ip_dashed in host_lower:
                continue
                
            filtered_domains.add(host)

        if filtered_domains:
            print(f"\n[+] Success pDNS Graph: Found \033[1m{len(filtered_domains)}\033[0m targets mapped to this IP:")
            for host in sorted(filtered_domains):
                print(f"    -> Associated Target: \033[1m{host}\033[0m")
        else:
            print(f"\n[!] Result: No real corporate domain found for the IP {target} (Only ISP noise filtered or no records).")