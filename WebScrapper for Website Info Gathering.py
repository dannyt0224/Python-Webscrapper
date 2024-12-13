from colorama import init, Fore
import requests
from bs4 import BeautifulSoup
import dns.resolver
import nmap
import sublist3r
from urllib.parse import urljoin, urlparse

init()
coloring_available = True

def color_text(text, color):
    if coloring_available:
        return f"{color}{text}{Fore.RESET}"
    return text

def gather_subdomains(domain):
    print(color_text(f"Gathering subdomains for {domain}...", Fore.BLUE))
    try:
        subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        print(color_text("Subdomains found:", Fore.GREEN), subdomains)
        return subdomains
    except IndexError:
        print(color_text(f"Error: Unable to extract subdomains for {domain}, likely due to a CSRF token issue.", Fore.RED))
        return []
    except Exception as e:
        print(color_text(f"Error gathering subdomains: {e}", Fore.RED))
        return []

def gather_technical_info(url):
    print(color_text(f"Gathering technical information for {url}...", Fore.BLUE))
    try:
        response = requests.get(url, timeout=10)
        response.encoding = response.apparent_encoding
        soup = BeautifulSoup(response.content, 'html.parser')
        title = soup.title.string if soup.title else 'No title found'
        meta_tags = {meta.attrs['name']: meta.attrs['content'] for meta in soup.find_all('meta') if 'name' in meta.attrs}
        print(color_text("Title:", Fore.GREEN), title)
        print(color_text("Meta Tags:", Fore.GREEN), meta_tags)
        return title, meta_tags
    except Exception as e:
        print(color_text(f"Error gathering technical info: {e}", Fore.RED))
        return None, {}

def scan_ports(target):
    print(color_text(f"Scanning ports for {target}...", Fore.BLUE))
    try:
        nm = nmap.PortScanner()
        nm.scan(target, '1-1024')
        open_ports = {}
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports[port] = nm[host][proto][port]
        print(color_text("Open Ports:", Fore.GREEN), open_ports)
        return open_ports
    except Exception as e:
        print(color_text(f"Error scanning ports: {e}", Fore.RED))
        return {}

def dns_lookup(domain):
    print(color_text(f"Performing DNS lookup for {domain}...", Fore.BLUE))
    try:
        result = dns.resolver.resolve(domain, 'A')
        records = [ip.to_text() for ip in result]
        print(color_text("DNS Records:", Fore.GREEN), records)
        return records
    except Exception as e:
        print(color_text(f"Error in DNS lookup: {e}", Fore.RED))
        return []

def site_mapping(base_url, max_depth=2):
    print(color_text(f"Mapping site structure for {base_url}...", Fore.BLUE))
    visited = set()
    to_visit = [(base_url, 0)]
    site_map = {}

    while to_visit:
        url, depth = to_visit.pop(0)
        if url in visited or depth > max_depth:
            continue
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            site_map[url] = [a['href'] for a in soup.find_all('a', href=True)]
            visited.add(url)
            for link in site_map[url]:
                absolute_link = urljoin(base_url, link)
                if urlparse(absolute_link).netloc == urlparse(base_url).netloc:
                    to_visit.append((absolute_link, depth + 1))
        except Exception as e:
            print(color_text(f"Error mapping site: {e}", Fore.RED))
            continue

    print(color_text("Site Map:", Fore.GREEN), site_map)
    return site_map

def main(target):
    if not target.startswith('http'):
        target = 'http://' + target

    domain = target.split('//')[1].split('/')[0]

    subdomains = gather_subdomains(domain)
    title, meta_tags = gather_technical_info(target)
    open_ports = scan_ports(domain)
    dns_records = dns_lookup(domain)
    site_map = site_mapping(target)

    print(color_text("\nSummary:", Fore.BLUE))
    print(color_text("Subdomains:", Fore.GREEN), subdomains)
    print(color_text("Title:", Fore.GREEN), title)
    print(color_text("Meta Tags:", Fore.GREEN), meta_tags)
    print(color_text("Open Ports:", Fore.GREEN), open_ports)
    print(color_text("DNS Records:", Fore.GREEN), dns_records)
    print(color_text("Site Map:", Fore.GREEN), site_map)

if __name__ == "__main__":
    target = input("Enter the target URL or domain: ")
    main(target)
