from dotenv import load_dotenv
import os
load_dotenv()
import scanners.dns as dns
import scanners.tls as tls
import scanners.was as was
import scanners.ports as ports
import scanners.email as email
import re
import ipaddress

def display_banner():
    print("========================================")
    print("                SENTINEL         ")
    print("                 v0.4 ")
    print("========================================")

def validate_and_identify_target(user_input):
    clean_input = user_input.strip()
    if not clean_input:
        return None, None

    try:
        ip_obj = ipaddress.ip_address(clean_input)
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            print("[!] Only public IP addresses are allowed.")
            return None, None
        return clean_input, "IP Address"
    except ValueError:
        pass

    domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.match(domain_pattern, clean_input):
        return clean_input, "Domain"

    print("[!] Invalid format. Please enter a valid public IP or Domain name (e.g., 8.8.8.8 or google.com).")
    return None, None

def get_target_input():
    while True:
        print("\n--- Target Input ---")
        user_input = input("Enter Target (Domain / Public IP) or 'q' to exit: ").strip().lower()
        
        if user_input == 'q':
            print("\nExiting program. Goodbye!")
            exit()
            
        target_value, target_type = validate_and_identify_target(user_input)
        if target_value:
            print("\n--- Target Selected ---")
            print(f"Type:  {target_type}")
            print(f"Value: {target_value}")
            print("========================================")
            return target_value, target_type

def sub_menu(target_value, target_type):
    while True:
        print(f"\n[ Current Target: {target_value} ({target_type}) ]")
        print("--- Assessment Menu ---")
        print("1. Graph PDNS")
        print("2. TLS/SSL")
        print("3. Web Application Headers")
        print("4. Open Ports")
        print("5. DMARC/DKIM/SPF")
        print("6. Full Scan")
        print("0. Change Target (New Domain/IP)")
        print("q. Quit")
        
        choice = input("Select an option: ").strip().lower()
        
        if choice == "1":
            dns.run(target_value, target_type)
        elif choice == "2":
            tls.run(target_value)
        elif choice == "3":
            was.run(target_value)
        elif choice == "4":
            ports.run(target_value)
        elif choice == "5":
            email.run(target_value)
        elif choice == "6":
            print("\n[*] Launching Full Suite Assessment...")
            dns.run(target_value, target_type)
            tls.run(target_value)
            was.run(target_value)
            ports.run(target_value)
            email.run(target_value)
        elif choice == "0":
            break
        elif choice == "q":
            print("\nExiting program. Goodbye!")
            exit()
        else:
            print("\n[!] Invalid choice. Please select a valid option.")
            continue

        print("\n" + "="*40)
        print("Scan execution finished.")
        print("1. Run another tool on CURRENT target")
        print("2. Scan a NEW Domain / IP")
        print("q. Quit Sentinel")
        print("="*40)
        
        after_action = input("What would you like to do? ").strip().lower()
        if after_action == "q":
            print("\nExiting program. Goodbye!")
            exit()
        elif after_action == "2":
            break 
        elif after_action == "1":
            print("\nReloading modules menu...")

def main():
    display_banner()
    while True:
        target_value, target_type = get_target_input()
        sub_menu(target_value, target_type)

if __name__ == "__main__":
    main()