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
    print("               SENTINEL         ")
    print("                  v0.3.0   ")
    print("========================================")

def option_domain():
  while True:
        user_domain = input("Enter domain (e.g., google.com): ").strip()
        pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if re.match(pattern, user_domain):
            print("\n--- Target Selected ---")
            print("Type: Domain")
            print(f"Value: {user_domain}")
            print("========================================")
            return user_domain
        else:
            print("[!] Invalid domain format. Try again (do not include http:// or slashes).")

def option_ip():
    while True:
        user_ip = input("Enter IP address (e.g., 8.8.8.8): ").strip()

        try:
            ip_obj = ipaddress.ip_address(user_ip)

            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                print("[!] Only public IP addresses are allowed.")
                continue

            print("\n--- Target Selected ---")
            print("Type: Public IP Address")
            print(f"Value: {user_ip}")
            print("========================================")
            return user_ip

        except ValueError:
            print("[!] Invalid IP address format. Please try again.")

def main_menu():
    while True:
        print("\n--- Select Target Type ---")
        print("1. Domain")
        print("2. IP address")
        print("q. Exit")
        
        choice = input("Select an option (1, 2, or 0): ").strip().lower()
        
        if choice == "1":
            target = option_domain()
            sub_menu(target, "Domain")
        elif choice == "2":
            target = option_ip()
            sub_menu(target, "IP Address")
        elif choice == "q":
            print("\nExiting program. Goodbye!")
            break
        else:
            print("\n[!] Invalid choice. Please enter 1, 2, or q.")

def sub_menu(target_value, target_type):
    while True:
        print("Current Target")
        print(f"{target_value}")
        print(f"{target_type}")
        print("--- Assessment Menu ---")
        print("1. DNS Analysis (Coming Soon)")
        print("2. TLS/SSL (Coming Soon)")
        print("3. Web Application Headers (Coming Soon)")
        print("4. Open Ports (Coming Soon)")
        print("5. DMARC/DKIM/SPF (Coming Soon)")
        print("6. Full Scan (Coming Soon)")
        print("0. Back to Main Menu")
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
            print("\nReturning to Main Menu...")
            break
        elif choice == "q":
            print("\nExiting program. Goodbye!")
            exit()
        else:
            print("\n[!] Invalid choice. Please select a valid module option.")
            continue # Skip the pause if the selection was totally invalid

        # === THE POST-SCAN INTERACTION GUARD ===
        # This code runs right after ANY scan (1-6) completes
        print("\n" + "="*40)
        print("Scan execution finished.")
        print("0. Show Menu Options Again")
        print("q. Quit Sentinel")
        print("="*40)
        
        after_action = input("What would you like to do? ").strip().lower()
        if after_action == "q":
            print("\nExiting program. Goodbye!")
            exit()
        elif after_action == "0":
            print("\nReloading menu layout...")

def main():
    display_banner()
    main_menu()

if __name__ == "__main__":
    main()