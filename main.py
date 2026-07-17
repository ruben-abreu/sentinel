def display_banner():
    print("========================================")
    print("               SENTINEL         ")
    print("                  v0.1   ")
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
        print("0. Exit")
        
        choice = input("Select an option (1, 2, or 0): ").strip()
        
        if choice == "1":
            option_domain()
        elif choice == "2":
            option_ip()
        elif choice == "0":
            print("\nExiting program. Goodbye!")
            break
        else:
            print("\n[!] Invalid choice. Please enter 1, 2, or 0.")

def main():
    display_banner()
    main_menu()

if __name__ == "__main__":
    main()