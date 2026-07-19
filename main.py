import scanners.dns as dns
import scanners.tls as tls
import scanners.was as was
import scanners.ports as ports
import scanners.email as email

def display_banner():
    print("========================================")
    print("               SENTINEL         ")
    print("                  v0.2   ")
    print("========================================")

def option_domain():
    user_domain = input("Enter domain: ").strip()
    print ("Target Selected")
    print("Type: Domain")
    print(f"Value: {user_domain} ")
    return user_domain

def option_ip():
    user_ip = input("Enter IP address: ").strip()
    print ("Target Selected")
    print("Type: IP Address")
    print(f"Value: {user_ip} ")
    return user_ip

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
            dns.run(target_value)
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
            dns.run(target_value)
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


def main():
    display_banner()
    main_menu()

if __name__ == "__main__":
    main()