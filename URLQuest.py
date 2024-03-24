import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from collections import Counter


def extract_domains(urls):
    domains = []
    for url in urls:
        parsed_url = urlparse(url)
        domain_parts = parsed_url.netloc.split('.')
        domain = '.'.join(['*'] + domain_parts[-2:])
        domains.append(domain)
    return domains

def suggest_firewall_urls(urls):
    """
    Suggests URLs to the user for adding to the firewall whitelist.

    Args:
        urls (set): A set of URLs.

    Returns:
        list: A list of suggested URLs.
    """
    domains = extract_domains(urls)

    domain_counter = Counter(domains)

    suggestions = []
    for domain, count in domain_counter.most_common():
        suggestion = f"*.{domain}"
        suggestions.append(suggestion)

    return suggestions

class CustomHelpFormatter(argparse.HelpFormatter):
    def _fill_text(self, text, width, indent):
        return ''.join(indent + line for line in text.splitlines(keepends=True))


def extract_urls(url, skip_duplicates=False):
    """
    Extracts URLs from the given webpage.

    Args:
        url (str): The URL of the webpage to inspect.
        skip_duplicates (bool): Whether to skip duplicated domains.

    Returns:
        set: A set of extracted URLs.
    """
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        parsed_url = urlparse(url)
        base_url = parsed_url.scheme + '://' + parsed_url.netloc

        urls = set()
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if href.startswith('http'):
                urls.add(href)
            elif href.startswith('/'):
                urls.add(base_url + href)
            else:
                urls.add(urljoin(base_url, href))

        if skip_duplicates:
            urls = filter_duplicates(urls)

        return urls
    except Exception as e:
        print(f"Error occurred: {e}")
        return set()

def extract_js_urls(url,skip_duplicates=False):
    """
    Extracts JavaScript URLs from the given webpage.

    Args:
        url (str): The URL of the webpage to inspect.

    Returns:
        set: A set of extracted JavaScript URLs.
    """
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        parsed_url = urlparse(url)
        base_url = parsed_url.scheme + '://' + parsed_url.netloc

        js_urls = set()
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src.startswith('http'):
                js_urls.add(src)
            elif src.startswith('//'):
                js_urls.add('https:' + src)
            else:
                js_urls.add(urljoin(base_url, src))

        if skip_duplicates:
            js_urls = filter_duplicates(js_urls)
        return js_urls
    except Exception as e:
        print(f"Error occurred: {e}")
        return set()

def extract_css_urls(url):
    """
    Extracts CSS URLs from the given webpage.

    Args:
        url (str): The URL of the webpage to inspect.

    Returns:
        set: A set of extracted CSS URLs.
    """
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        parsed_url = urlparse(url)
        base_url = parsed_url.scheme + '://' + parsed_url.netloc

        css_urls = set()
        for link in soup.find_all('link', rel='stylesheet', href=True):
            href = link.get('href')
            if href.startswith('http'):
                css_urls.add(href)
            elif href.startswith('//'):
                css_urls.add('https:' + href)
            else:
                css_urls.add(urljoin(base_url, href))

        return css_urls
    except Exception as e:
        print(f"Error occurred: {e}")
        return set()

def extract_image_urls(url):
    """
    Extracts image URLs from the given webpage.

    Args:
        url (str): The URL of the webpage to inspect.

    Returns:
        set: A set of extracted image URLs.
    """
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        parsed_url = urlparse(url)
        base_url = parsed_url.scheme + '://' + parsed_url.netloc

        image_urls = set()
        for img in soup.find_all('img', src=True):
            src = img.get('src')
            if src.startswith('http'):
                image_urls.add(src)
            elif src.startswith('//'):
                image_urls.add('https:' + src)
            else:
                image_urls.add(urljoin(base_url, src))

        return image_urls
    except Exception as e:
        print(f"Error occurred: {e}")
        return set()

def extract_font_urls(url):
    """
    Extracts font URLs from the given webpage.

    Args:
        url (str): The URL of the webpage to inspect.

    Returns:
        set: A set of extracted font URLs.
    """
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        parsed_url = urlparse(url)
        base_url = parsed_url.scheme + '://' + parsed_url.netloc

        font_urls = set()
        for link in soup.find_all('link', rel='stylesheet', href=True):
            href = link.get('href')
            if href.endswith('.woff') or href.endswith('.woff2') or href.endswith('.ttf'):
                if href.startswith('http'):
                    font_urls.add(href)
                elif href.startswith('//'):
                    font_urls.add('https:' + href)
                else:
                    font_urls.add(urljoin(base_url, href))

        return font_urls
    except Exception as e:
        print(f"Error occurred: {e}")
        return set()

def filter_duplicates(urls):
    """
    Filters out duplicated domains from the given set of URLs.

    Args:
        urls (set): A set of URLs.

    Returns:
        set: A set of URLs with duplicated domains filtered out.
    """
    domains = set()
    filtered_urls = set()
    for url in urls:
        domain = urlparse(url).netloc
        if domain not in domains:
            domains.add(domain)
            filtered_urls.add(url)
    return filtered_urls


def extract_html_urls(url):
    """
    Extracts HTML URLs from the given webpage.

    Args:
        url (str): The URL of the webpage to inspect.

    Returns:
        set: A set of extracted HTML URLs.
    """
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        parsed_url = urlparse(url)
        base_url = parsed_url.scheme + '://' + parsed_url.netloc

        html_urls = set()
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if href.endswith('.html') or href.endswith('.htm'):
                if href.startswith('http'):
                    html_urls.add(href)
                elif href.startswith('/'):
                    html_urls.add(base_url + href)
                else:
                    html_urls.add(urljoin(base_url, href))

        return html_urls
    except Exception as e:
        print(f"Error occurred: {e}")
        return set()

def extract_all_headers(url):
    """
    Extracts all headers from the HTTP response of the given URL.

    Args:
        url (str): The URL to extract headers from.

    Returns:
        dict: A dictionary containing all headers and their values.
    """
    try:
        response = requests.get(url)
        headers = response.headers

        # Extract all headers
        extracted_headers = {}
        for header, value in headers.items():
            extracted_headers[header] = value

        return extracted_headers
    except Exception as e:
        print(f"Error occurred: {e}")
        return None


def extract_robots_txt(url):
    """
    Extracts the contents of the robots.txt file for the given URL.

    Args:
        url (str): The URL to extract the robots.txt file from.

    Returns:
        str: The contents of the robots.txt file, or an error message if not found.
    """
    try:
        robots_url = urljoin(url, "/robots.txt")
        response = requests.get(robots_url)
        if response.status_code == 200:
            robots_txt_content = response.text
            return robots_txt_content
        else:
            return "robots.txt not found"
    except Exception as e:
        print(f"Error occurred: {e}")

def extract_cookies(url):
    """
    Extracts cookies from the HTTP response of the given URL.

    Args:
        url (str): The URL to extract cookies from.

    Returns:
        dict: A dictionary containing cookie names and their attributes.
    """
    try:
        response = requests.get(url)
        cookies = response.cookies
        extracted_cookies = {}
        for cookie in cookies:
            extracted_cookies[cookie.name] = {
                'value': cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'httponly': cookie.secure,
                'expires': cookie.expires
            }

        return extracted_cookies
    except Exception as e:
        print(f"Error occurred: {e}")
        return None


def extract_security_headers(url):
    """
    Extracts security-related headers from the provided URL.

    Args:
        url (str): The URL of the webpage to inspect.

    Returns:
        dict: A dictionary containing security-related headers and their values.
                Keys represent header names, and values represent header values.
                Returns None if an error occurs during extraction.
    """
    try:
        response = requests.get(url)

        security_headers = {
            'Content-Security-Policy': response.headers.get('Content-Security-Policy', None),
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', None),
            'X-Frame-Options': response.headers.get('X-Frame-Options', None),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection', None),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', None)
        }

        return security_headers
    except Exception as e:
        print(f"Error occurred: {e}")
        return None



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"{'='*45}\n\t\t  URLQuest!\n{'='*45}",formatter_class=CustomHelpFormatter,epilog="- USAGE: A tool designed to help you collect website links and data, and also suggest which domains and wildcards to use when statically allowing/blocking certain websites in the firewall.\n- Version: 0.1\n- Date: 24-March-2024\n\n- Written by: Ahmed Osama Elshimy\n- LinkedIn: ahmedosamaelshimy")
    parser.add_argument('url', help='URL of the webpage to inspect')
    parser.add_argument('--skip-duplicates', action='store_true', help='Skip duplicated domains')
    parser.add_argument('--extract-urls', action='store_true', help='Extract URLs')
    parser.add_argument('--extract-js-urls', action='store_true', help='Extract JavaScript URLs')
    parser.add_argument('--extract-css', action='store_true', help='Extract CSS URLs')
    parser.add_argument('--extract-images', action='store_true', help='Extract image URLs')
    parser.add_argument('--extract-fonts', action='store_true', help='Extract font URLs')
    parser.add_argument('--extract-htmls', action='store_true', help='Extract HTML URLs')
    parser.add_argument('--extract-all', action='store_true', help='Extract All URLs')
    parser.add_argument('--suggest', action='store_true', help='Suggests URLs to the user that can be added to the firewall whitelist. , Note: --extract-all option is a MUST')
    parser.add_argument('--extract-sec-headers', action='store_true', help='Extract Security Headers')
    parser.add_argument('--extract-all-headers', action='store_true', help='Extract all headers from the HTTP response')
    parser.add_argument('--extract-robots-txt', action='store_true', help='Extract the contents of the robots.txt file')
    parser.add_argument('--extract-cookies', action='store_true', help='Extract cookies from the HTTP response')

    args = parser.parse_args()


    if args.extract_all:
        args.extract_urls = True
        args.extract_js_urls = True
        args.extract_css = True
        args.extract_images = True
        args.extract_fonts = True
        args.extract_htmls =True

    if args.extract_urls:
        print(f"{'*' * 40}")

        print("Extracting URLs...")
        urls = extract_urls(args.url, args.skip_duplicates)

        if urls != None:
            print(f"{'*'*10} Found URLs {'*'*10}")
            for url in urls:
                print("-",url)
        else:
            print("No URLs Found")
        print(f"{'*' * 40}\n")

    if args.extract_js_urls:
        print("Extracting JavaScript URLs...")
        js_urls = extract_js_urls(args.url)
        if js_urls != None:
            print(f"{'*'*10} Found JavaScript URLs {'*'*10}")
            for js_url in js_urls:
                print("-",js_url)
        else:
            print("No JavaScript URLs Found")
        print(f"{'*' * 40}\n")

    if args.extract_css:
        print(f"{'*' * 40}")

        print("Extracting CSS URLs...")
        css_urls = extract_css_urls(args.url)
        if css_urls != None:
            print(f"{'*'*10} Found CSS URLs {'*'*10}")
            for css_url in css_urls:
                print("-",css_url)
        else:
            print("No CSS URLs Found")

        print(f"{'*' * 40}\n")


    if args.extract_images:
        print(f"{'*' * 40}")

        print("Extracting Image URLs...")
        image_urls = extract_image_urls(args.url)
        if len(image_urls) != 0:
            print(f"{'*'*10} Found Image URLs {'*'*10}")
            for image_url in image_urls:
                print("-",image_url)
        else:
            print("No Image URLs Found")
        print(f"{'*' * 40}\n")



    if args.extract_fonts:
        print(f"{'*' * 40}")

        print("Extracting Font URLs...")
        font_urls = extract_font_urls(args.url)

        if len(font_urls) !=0:
            print(f"{'*'*10} Found Font URLs {'*'*10}")
            for font_url in font_urls:
                print("-",font_url)
        else:
            print("No Font URLs Found")

        print(f"{'*' * 40}\n")

    if args.extract_htmls:
        print(f"{'*' * 40}")

        print("Extracting HTML URLs...")
        html_urls = extract_font_urls(args.url)

        if len(html_urls) !=0:
            print(f"{'*'*10} Found HTML URLs {'*'*10}")
            for html_url in html_urls:
                print("-",html_url)
        else:
            print("No HTML URLs Found")
        print(f"{'*' * 40}\n")



    if args.extract_all:
        if args.suggest:
            print("\n")
            print("\n")
            print(f"{'*' * 40} Suggestions {'*' * 40}")
            all_urls_found = urls |js_urls| css_urls|html_urls|image_urls | font_urls
            suggestions = suggest_firewall_urls(all_urls_found)
            for suggestion in suggestions:
                print("-",suggestion)
            print("\nNote: Please Validate these suggestions before adding it to the whitelist.")
            print(f"{'*' * 80}")

    if args.extract_sec_headers:
        print("Extracting Security Headers...")
        security_headers = extract_security_headers(args.url)
        if security_headers:
            print("Security Headers:")
            for header, value in security_headers.items():
                print( f"- {header}: {value}\n")
        else:
            print("Failed to extract security headers.")
    if args.extract_all_headers:
        all_headers = extract_all_headers(args.url)
        if all_headers:
            print("All Headers:")
            for header, value in all_headers.items():
                print(f"- {header}: {value}\n")
        else:
            print("Failed to extract headers.")
    if args.extract_robots_txt:
        robots_txt = extract_robots_txt(args.url)
        print("Robots.txt Contents:")
        print(robots_txt)

    if args.extract_cookies:
        cookies = extract_cookies(args.url)
        if cookies:
            print("Extracted Cookies:")
            for name, details in cookies.items():
                print(f"- Name: {name}")
                print(f"- Details: {details}\n")
        else:
            print("Failed to extract cookies.")

