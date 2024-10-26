import requests
import argparse
from urllib.parse import urljoin
from colorama import Fore, Style, init
from requests.exceptions import ConnectionError

init(autoreset=True)

creator_name = "Aung San Oo"
creator_website = "https://aungsanoo.com"

print(f"{Fore.CYAN}Admin Login Finder Tool")
print(f"Created by: {creator_name}")
print(f"Website: {creator_website}{Style.RESET_ALL}\n")

generic_admin_paths = [
    "admin/", "admin/login", "administrator/", "admin1/", "admin2/", 
    "admin3/", "admin4/", "admin5/", "usuarios/", "usuario/", "administrator", 
    "moderator/", "webadmin/", "adminarea/", "bb-admin/", "adminLogin/", 
    "admin_area/", "panel-administracion/", "instadmin/", "memberadmin/", "wp-admin",
    "/admin.%XT%", "/login/", "/login.%XT%", "/adm/", "/admin/", "phpinfo.php",
    "/adminitem/", "/adminitem.%XT%", "/adminitems/", "/adminitems.%XT%", 
    "/administrator.%XT%", "/administration/", "/administration.%XT%", 
    "/adminLogin/", "/adminlogin.%XT%", "/admin_area/admin.%XT%", "/admin_area/",
    "/admin_area/login.%XT%", "/access/", "/acct_login/", "/_adm_/", "/_adm/", 
    "/adm/", "/adm2/", "/_admin_/", "/_admin/", "/admin/", "/Admin/", "/ADMIN/", 
    "/phpMyAdmin/", "/phpmyadmin/", "/PMA/", "/admin/", "/dbadmin/", "/mysql/", 
    "/myadmin/", "/phpmyadmin2/", "/phpMyAdmin2/", "/phpMyAdmin-2/", "/php-my-admin/"
]

php_admin_paths = [
    "admin.php", "administrator/index.php", "admin/login.php", "adminpanel.php", 
    "cpanel.php", "login.php", "admin_area/login.php", "admin_area/index.php",
    "controlpanel.php", "admincp.php", "adminLogin.php", "adm.php", "adminpage.php",
    "admin/index.php", "admin/login.php", "admin_area/admin.php", "admin_area/login.php",
    "cms/admin.php", "admincontrol/login.php", "admincontrol/index.php", 
    "admin/administrator.php", "admin/user.php", "admin/log.php", "admin/member.php", 
    "admin/logon.php", "admin_console.php", "administrator/admin.php",
    "admin/admin_area.php", "adminpanel/admin_login.php", "admin_area/admin_login.php", 
    "admin_login/admin.php", "admin_manager.php", "admin/main.php", "manager.php",
    "admin_control.php", "adminlogin.php", "panel.php","wp-login.php", "wp-admin/", 
    "wp-admin/admin.php", "wp-login.php?action=register", "wp-admin/setup-config.php", 
    "wp-admin/admin-post.php", "wp-admin/admin-ajax.php", "wp-admin/network/", 
    "wp-admin/user-new.php", "wp-admin/options-general.php", "wp-admin/edit.php", 
    "wp-admin/themes.php", "wp-admin/plugins.php", "wp-admin/customize.php", 
    "wp-admin/profile.php"
]

asp_admin_paths = [
    "admin.asp", "admin/login.asp", "administrator/index.asp", "admin_area/login.asp", 
    "admin_area/index.asp", "controlpanel.asp", "admincp.asp", "adminLogin.asp",
    "adm/admloginuser.asp", "adm/admloginuser.php", "adm.asp", "adm_auth.asp",
    "adm.asp", "login.asp", "adminpage.asp", "cpanel.asp", "admin_login.asp",
    "admin/index.asp", "admin/login.asp", "admin_area/admin.asp", "admin_area/login.asp",
    "cms/admin.asp", "admincontrol/login.asp", "admincontrol/index.asp",
    "admin/administrator.asp", "admin/user.asp", "admin/log.asp", "admin/member.asp", 
    "admin/logon.asp", "admin_console.asp", "administrator/admin.asp",
    "admin/admin_area.asp", "adminpanel/admin_login.asp", "admin_area/admin_login.asp", 
    "admin_login/admin.asp", "admin_manager.asp", "admin/main.asp", "manager.asp",
    "admin_control.asp", "adminlogin.asp", "panel.asp"
]

admin_subdomains = [
    "admin", "cpanel", "webmail", "dashboard", "manage", "controlpanel", 
    "secure", "portal", "support", "helpdesk", "login", "webadmin", "staff"
]

def check_admin_login(url, admin_paths):
    found_admin_panels = []
    false_positive_texts = [
        "The page you were looking for doesn't exist", 
        "404 Not Found", 
        "Page Not Found",
        "Error 404",
        "This page could not be found"
    ]
    for path in admin_paths:
        test_url = urljoin(url, path)
        print(f"{Fore.YELLOW}Scanning: {test_url}{Style.RESET_ALL}")
        try:
            response = requests.get(test_url, verify=True)
            if response.status_code == 200:
                if any(false_text in response.text for false_text in false_positive_texts):
                    print(f"{Fore.RED}[-] False positive detected at: {test_url}{Style.RESET_ALL}")
                    continue
                found_admin_panels.append(test_url)
                print(f"{Fore.GREEN}[+] Admin login found: {test_url}{Style.RESET_ALL}")
            elif response.status_code == 403:
                print(f"[*] 403 Forbidden at {test_url}")
        except requests.exceptions.ConnectionError:
            print(f"{Fore.RED}[-] Connection error for {test_url} - Could not resolve host.{Style.RESET_ALL}")
        except requests.exceptions.RequestException as e:
            print(f"[-] Error for {test_url}: {e}")
    return found_admin_panels

def is_subdomain_reachable(subdomain_url):
    try:
        response = requests.get(subdomain_url, verify=True, timeout=5)
        return response.status_code < 400
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}[-] Connection error for {subdomain_url} - Subdomain does not exist.{Style.RESET_ALL}")
        return False
    except requests.exceptions.RequestException:
        return False

def check_admin_subdomains(domain, admin_paths):
    domain = domain.lstrip("www.")
    found_admin_panels = []
    for subdomain in admin_subdomains:
        subdomain_url = f"https://{subdomain}.{domain}"
        print(f"{Fore.YELLOW}Checking subdomain: {subdomain_url}{Style.RESET_ALL}")
        if is_subdomain_reachable(subdomain_url):
            found_admin_panels.extend(check_admin_login(subdomain_url, admin_paths))
        else:
            print(f"{Fore.YELLOW}[-] Skipping scan for {subdomain_url} as it is not reachable.{Style.RESET_ALL}")
    return found_admin_panels

def main():
    parser = argparse.ArgumentParser(description="Admin Login Finder Tool")
    parser.add_argument("url", help="Target URL (e.g., https://example.com)")
    args = parser.parse_args()
    url = args.url.strip()
    
    domain = url.split("//")[-1].split("/")[0]  

    print("Choose Technology:")
    print("1. PHP")
    print("2. ASP")
    print("3. All (General)")
    
    tech_choice = input("Enter choice (1, 2, or 3): ").strip()
    
    if tech_choice == "1":
        admin_paths = generic_admin_paths + php_admin_paths
        print("[*] Running Admin Login Finder for PHP paths...")
    elif tech_choice == "2":
        admin_paths = generic_admin_paths + asp_admin_paths
        print("[*] Running Admin Login Finder for ASP paths...")
    elif tech_choice == "3":
        admin_paths = generic_admin_paths + php_admin_paths + asp_admin_paths
        print("[*] Running Admin Login Finder for All paths...")
    else:
        print("[-] Invalid choice for technology. Please restart the tool and choose a valid option.")
        return

    print(f"{Fore.CYAN}[*] Checking main domain for admin panels...{Style.RESET_ALL}")
    main_domain_panels = check_admin_login(url, admin_paths)
    
    print(f"{Fore.CYAN}[*] Checking common admin subdomains for admin panels...{Style.RESET_ALL}")
    subdomain_panels = check_admin_subdomains(domain, admin_paths)
    
    all_found_panels = main_domain_panels + subdomain_panels

    if not all_found_panels:
        print(f"{Fore.RED}[-] No accessible admin panels found.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[*] Accessible admin panels found:{Style.RESET_ALL}")
        for panel in all_found_panels:
            print(panel)

if __name__ == "__main__":
    main()
