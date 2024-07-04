import requests
import os

def update_script():
    url = "https://raw.githubusercontent.com/kar-ik/network_scanner.py"
    response = requests.get(url)
    
    if response.status_code == 200:
        with open("network_scanner.py", "w") as file:
            file.write(response.text)
        print("The tool has been updated successfully.")
    else:
        print("Failed to update the tool. Please check the URL or your internet connection.")

def main():
    choice = input("Do you want to update the tool? (yes/no): ").strip().lower()
    if choice == 'yes':
        update_script()
    else:
        print("Update canceled.")

if __name__ == "__main__":
    main()
