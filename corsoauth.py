#!/usr/bin/env python3

from requests.exceptions import SSLError, ConnectionError, ReadTimeout
from urllib3.exceptions import NewConnectionError, MaxRetryError, ReadTimeoutError
from urllib.parse import urlparse, urlunparse, urljoin, urldefrag
from bs4 import BeautifulSoup

import traceback
import argparse
import requests
import random
import string
import json
import time
import sys
import os
import re

# =============================================================================
# =============================================================================
# ================================= FUNCTIONS =================================
# =============================================================================
# =============================================================================

# =============================================================================
# ========================= Basic crawling functions ==========================
# =============================================================================

def get_template_url(url, _path=True):
    """
    Returns the template of the passed URL. The template contains:
    - the netloc (domain)
    - the path (if path=True)
    Everything else is removed.
    """
    try:
        parsed = urlparse(urldefrag(url)[0])
        if _path:
            return urlunparse(('', parsed.netloc, parsed.path, '', '', ''))
        else:
            if len(parsed.path.split('/')) > 1:
                path = parsed.path.replace(parsed.path.split('/')[-1], '')
            else:
                path = parsed.path
            return urlunparse(('', parsed.netloc, re.sub('\d+', '', path), '', '', ''))
    except:
        debug(traceback.format_exc(), file=sys.stderr)
        return None

def get_domain_name(url):
    """
    Returns the domain name of the passed URL
    (Ignore top level domain and subdomains).
    """
    try:
        if url.startswith('http') and '//' in url:
            parsed = urlparse(urldefrag(url)[0])
            split_netloc = parsed.netloc.replace('www.', '').split('.')
        else:
            split_netloc = url.split('.')
        if len(split_netloc) > 2:
            if len(split_netloc[-2]) > 3:
                return split_netloc[-2]
            else:
                return split_netloc[-3]
        elif len(split_netloc) == 2:
            return split_netloc[-2]
        else:
            return ''
    except:
        debug(url, split_netloc)
        debug(traceback.format_exc(), file=sys.stderr)
        return None

def get_domain(url):
    """
    Returns the domain name of the passed URL.
    """
    return urlparse(url).netloc

def is_internal_url(url):
    """
    Returns True if the url is internal to the website.
    Ignores the top level domain:
    e.g., google.com and google.it are considered the same domain.
    """
    try:
        if not url.startswith('http'):
            url = 'http://' + url
        parsed = urlparse(url)
        if get_domain_name(parsed.netloc).endswith(get_domain_name(SITE)):
            return True
        else:
            return False
    except:
        debug(traceback.format_exc(), file=sys.stderr)
        return False

def get_links(page_url, html, only_internal=True):
    """
    Receives a URL and the body of the web page
    and returns a set of all links found in the
    page that are internal (meaning that are on
    the same site)
    """
    links = []

    try:
        soup = BeautifulSoup(html, 'html.parser')

        for link in soup.find_all('a', href=True):
            url = urljoin(clean_url(page_url), clean_url(link['href']))

            if 'http' in url and only_internal and is_internal_url(url):
                links.append(clean_url(urldefrag(url)[0]))

            elif not only_internal:
                _url = clean_url(urldefrag(url)[0])
                if any([i in _url for i in BLACKLISTED_DOMAINS]):
                    continue

                links.append(_url)
    except:
        debug(traceback.format_exc(), file=sys.stderr)

    return sorted(links)

def get_source_code_links(url, html):
    """
    Returns a list of all links found in the
    source code of the passed page.
    """

    cleaned_url = url.replace('_', '').replace('-', '').replace('.', '').lower()
    links = []

    # Find links in the source code using regular expressions
    regex_links = re.findall("((?:https?:\/\/|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}\/)(?:[^\s()<>\"\']+|\(([^\s()<>\"\']+|(\([^\s()<>\"\']+\)))*\))+(?:\(([^\s()<>\"\']+|(\([^\s()<>\"\']+\)))*\)|[^\s`!()\[\]{};:'\".,<>?]))", html)
    links = [''.join(link) for link in regex_links if not any([i in link for i in BLACKLISTED_DOMAINS])]

    soup = BeautifulSoup(html, 'html.parser')
    # and in tags that have an href
    for link in soup.find_all(href=True):
        href = link['href']
        links.append(urljoin(url, href))
    # and in forms actions
    forms = soup.find_all('form')
    for form in forms:
        try:
            action = form.get('action')
            if action != None:
                links.append(urljoin(url, action))
        except:
            pass

    # and in buttons (action, href, data-url, data-href, ecc)
    buttons = soup.find_all('button')
    for button in buttons:
        try:
            action = urljoin(url, button.get('action'))
            if action != None:
                links.append(action)
        except:
            pass

    for button in buttons:
        try:
            # TODO: Consider here going through all the attributes of the button?
            data_url = button.get('data-url')
            if data_url != None:
                links.append(urljoin(url, data_url))
            data_href = button.get('data-href')
            if data_href != None:
                links.append(urljoin(url, data_href))
            formaction = button.get('formaction')
            if formaction != None:
                links.append(urljoin(url, formaction))
        except:
            pass
    
    return links

def add_to_queue(url):
    """
    Add a url to the queue if it is not already in the queue
    and if its template is not already in the visited list.
    """
    try:
        domain  = get_domain(url)

        if not is_visited(url):
            if domain not in queue:
                queue[domain] = []
            if url not in queue[domain]:
                queue[domain].append(url)
    except:
        if DEBUG:
            print(traceback.format_exc(), file=sys.stderr)

def add_to_visited(url):
    """
    Add a url to the visited list.
    """
    try:
        if not is_visited(url):
            domain  = get_domain(url)
            if domain not in visited_urls:
                visited_urls[domain] = []

            template_url = get_template_url(url)
            visited_urls[domain].append(template_url)

    except:
        if DEBUG:
            print(traceback.format_exc(), file=sys.stderr)

def is_visited(url):
    """
    Return True if the template of the url
    is in the visited list.
    """
    try:
        domain  = get_domain(url)
        if not domain in visited_urls:
            return False

        template_url = get_template_url(url)
        if template_url is not None and \
            template_url in visited_urls[domain]:
            return True
        else:
            return False
    except:
        if DEBUG:
            print(traceback.format_exc(), file=sys.stderr)
    return False

def get_url_from_queue(visited=False):
    """
    Return the first not visited url in the queue
    if the visited list for this domain is not full.
    """
    domains = list(queue.keys())
    random.shuffle(domains)

    try:
        for domain in domains:
            # If the visited list for this domain
            # is full, choose a new domain
            if domain in visited_urls and \
                len(visited_urls[domain]) >= MAX:
                continue
            else:
                # Pop the first url in the queue
                # for this domain
                while len(queue[domain]) > 0:
                    url = queue[domain].pop(0)
                    if not is_visited(url):
                        if visited:
                            add_to_visited(url)
                        return url
    except:
        if DEBUG:
            print(traceback.format_exc(), file=sys.stderr)
    return None

def should_continue():
    """
    Return True if the queue is not empty
    and the visited list is not full.
    """
    try:
        for domain in queue:
            if domain not in visited_urls or \
                (len(visited_urls[domain]) < MAX and \
                    len(queue[domain]) > 0):
                return True
    except:
        if DEBUG:
            print(traceback.format_exc(), file=sys.stderr)
    return False

# =============================================================================
# ============================== CORS functions ===============================
# =============================================================================

def generate_variations(origin):
    parsed = urlparse(origin)
    variations = {}

    # 1: prefix matching
    variations['prefix_matching'] = (origin + f'.{get_random_string(4, 4).lower()}.com')

    # 2: suffix matching
    variations['suffix_matching'] = (origin.split('//')[0] + f'//{get_random_string(4, 4).lower()}' + origin.replace(origin.split('//')[0] + '//', '').replace('www.', ''))

    # 3: not escaping '.'
    variations['non_escaped_dot'] = 'a'.join(origin.split('.'))

    # 4: substring matching
    variations['substring_matching'] = (origin.split('//')[0] + '//aaa' + origin.split('://')[1][1:-1])

    # 5: value 'null'
    variations['null_value'] = ('null')

    # 6: https trusts http
    variations['https_trusts_http'] = origin.replace('https://', 'http://')

    # 7: arbitrary subdomain
    if len(parsed.netloc.split('.')) > 2:
        domain = '.'.join(parsed.netloc.split('.')[1:])
    else:
        domain = parsed.netloc
    variations['arbitrary_subdomain'] = (f'{parsed.scheme}://{get_random_string(4, 4).lower()}.{domain}')

    # 8: arbitrary origin reflection
    variations['arbitrary_origin_reflection'] = (f'{parsed.scheme}://{get_random_string(7, 7).lower()}.com')

    return variations

def check_origin(headers, origin, _log=True):
    """
    Return a tuple containing
    - True if the Origin is allowed, False otherwise and
    - the value of the Access-Control-Allow-Origin header
    """
    if 'access-control-allow-origin' in headers:
        header = headers['access-control-allow-origin']

        # What if the Origin does not match but it gives allow anyway?
        return header == origin or \
                header == '*'    or \
                header == 'null', header
    else:
        return False, ''

def test_url(url, headers):
    """
    Tests a URL for CORS misconfigurations
    """
    global statisitcs, report
    parsed = urlparse(url)
    origin = parsed.scheme + '://' + parsed.netloc
    if len(headers) == 0:
        headers = {
            'Origin': origin,
            'User-Agent': USER_AGENT,
        }

    # Check if the site is using CORS on the URL to test
    response = session.get(url, headers=headers)
    if url not in report:
        report[url] = {}
    report[url]['original'] = {
        'Origin': origin,
        'response_headers': dict(response.headers),
        'request_headers':  dict(response.request.headers)
    }

    successful, header = check_origin(response.headers, origin)

    # If the site is using CORS and does not accept
    # everything as an Origin: test the variations
    if successful and header != '*':
        log(f'Original: {bcolors.OKBLUE}{origin}{bcolors.ENDC} on {url}')
        statistics['cors'] = True

        # Generate the variations based on the allowed Origin
        variations = generate_variations(origin)
        count = 0
        for variation in variations:
            count += 1
            if args.variations and count not in VARIATIONS:
                continue

            _headers = headers.copy()
            _headers['Origin'] = variations[variation]

            response = session.get(url, headers=_headers)
            if url not in report:
                report[url] = {}
            report[url][variation] = {
                'Origin': variations[variation],
                'response_headers': dict(response.headers),
                'request_headers':  dict(response.request.headers)
            }

            successful, header = check_origin(response.headers, variations[variation])

            if successful:
                log(f'{bcolors.FAIL}{variation}{bcolors.ENDC} ({bcolors.OKBLUE}{variations[variation]}{bcolors.ENDC}): {url} vulnerable')

                statistics['vulnerable'] = True
                if url not in statistics['vulnerable_urls']:
                    statistics['vulnerable_urls'][url] = []
                if variation not in statistics['vulnerable_urls'][url]:
                    statistics['vulnerable_urls'][url].append(variation)

                if variation not in statistics['variations']:
                    statistics['variations'].append(variation)
            else:
                log(f'{variation} ({bcolors.WARNING}{variations[variation]}{bcolors.ENDC}): {url} not vulnerable')

    elif header == '*':
        statistics['cors'] = True
        statistics['wildcard'] = True
        log(f'Wildcard')
        if url not in report:
            report[url] = {}
        report[url]['wildcard'] = {
            'Origin': '*',
            'response_headers': dict(response.headers),
            'request_headers':  dict(response.request.headers)
        }

        if 'access-control-allow-credentials' in response.headers and \
            response.headers['access-control-allow-credentials'] == 'true':
            statistics['vulnerable']    = True
            statistics['credentials']   = True
            log(f'Original: {bcolors.WARNING}{origin}{bcolors.ENDC}: {url} allows wildcard with credentials')

        else:
            statistics['credentials'] = False
            log(f'Original: {bcolors.WARNING}{origin}{bcolors.ENDC}: {url} allows wildcard')
    else:
        log(f'Original: {bcolors.WARNING}{origin}{bcolors.ENDC}: {url} not using CORS')

# =============================================================================
# ====================== Login detection functions ============================
# =============================================================================

def get_login_url(urls):
    """
    Return the login url from the list of urls (if present).
    """
    for url in urls:
        cleaned_url = url.replace('_', '').replace('-', '').replace('.', '').lower()
        # print(f'{bcolors.OKGREEN}[+]{bcolors.ENDC} {url}')

        if '/signin' in cleaned_url or \
            '/login' in cleaned_url and \
            '/join'  in cleaned_url and  \
            not '/hc/' in cleaned_url: # Ignore Zendesk support pages
            # print(f'Login url found: {bcolors.OKGREEN}{url}{bcolors.ENDC} because contains /login or /signin')
            return url

    for url in urls:
        cleaned_url = url.replace('_', '').replace('-', '').replace('.', '').lower()

        if 'signin' in cleaned_url or \
            'login' in cleaned_url and \
            not '/hc/' in cleaned_url:
            # print(f'Login url found: {bcolors.OKGREEN}{url}{bcolors.ENDC} because contains login or signin')
            return url
    return ''

def is_login_page(url, html):
    """
    Return True if the current page is a login PAGE.
    """
    cleaned_url = url.replace('_', '').replace('-', '').replace('.', '').lower()

    # print(f'Test if it\'s a login page! Cleaned url: {url}')

    if 'login' in cleaned_url or \
        'signin' in cleaned_url:
        # print(f'Is login page because contains {bcolors.OKGREEN}login/signin{bcolors.ENDC}')
        return True
    
    soup = BeautifulSoup(html, 'html.parser')
    password = soup.find('input', {'type' : 'password'})
    if password is not None:
        # print(f'Is login page because contains {bcolors.OKGREEN}a type=password input field{bcolors.ENDC} {password}')
        return True
    # print(f'Is not login page')
    return False

# =============================================================================
# ============================= Helper functions ==============================
# =============================================================================

def log(message='', file=sys.stdout, end='\n'):
    print(f'[LOG {SITE}] {message}', file=file, end=end, flush=True)

def debug(message, file=sys.stderr, end='\n'):
    if DEBUG:
        print(f'[DEBUG {SITE}] {message}', file=file, end=end, flush=True)

def get_random_string(start=10, end=20):
    return ''.join(random.choice(string.ascii_letters + string.digits + '_') for _ in range(random.randint(start, end)))

def clean_url(url):
    """
    Cleans the url to remove any trailing newlines and spaces.
    """
    return url.strip().strip('\n')

def save_dictionaries(site, stats_dir, reports_dir, logs_dir):
    """
    Save the dictionaries to the files.
    """
    global statistics, urls_to_test, report, tested, queue, visited_urls

    if not os.path.exists(stats_dir):
        os.makedirs(stats_dir)
    with open(f'{stats_dir}/{site}-statistics.json', 'w') as f:
        json.dump(statistics, f, indent=4)

    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    with open(f'{reports_dir}/{site}-report.json', 'w') as f:
        json.dump(report, f) # not indented to save space

    logs = {
        'urls_to_test': urls_to_test,
        'tested':       tested,
        'queue':        queue,
        'visited':      visited_urls
    }
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    with open(f'{logs_dir}/{site}-log.json', 'w') as f:
        json.dump(logs, f, indent=4)

def get_dictionaries():
    """
    Load the dictionaries from the files.
    """
    global statistics, urls_to_test, report, tested, queue, visited_urls
    if os.path.exists(f'{STATS}/{SITE}-statistics.json'):
        with open(f'{STATS}/{SITE}-statistics.json', 'r') as f:
            statistics = json.load(f)

    if os.path.exists(f'{REPORTS}/{SITE}-report.json'):
        with open(f'{REPORTS}/{SITE}-report.json', 'r') as f:
            report = json.load(f)

    if os.path.exists(f'{LOGS}/{SITE}-log.json'):
        with open(f'{LOGS}/{SITE}-log.json', 'r') as f:
            logs = json.load(f)
            urls_to_test    = logs['urls_to_test']
            tested          = logs['tested']
            queue           = logs['queue']
            visited_urls    = logs['visited']

# =============================================================================
# =============================================================================
# ============================== GLOBAL VARIABLES =============================
# =============================================================================
# =============================================================================

class bcolors:
    HEADER  = '\033[95m'
    OKBLUE  = '\033[94m'
    OKCYAN  = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'
    BOLD    = '\033[1m'
    UNDERLINE = '\033[4m'

# Dictionaries where the key is the domain and the value is a list of URLs
queue = {}
visited_urls = {}

# Statistics dictionary
statistics = {
    'site':         '',
    'cors':         False,
    'vulnerable':   False,
    'wildcard':     False,
    'credentials':  False,
    'vulnerable_urls':  {},
    'variations':       []
}

# Report dictionary
report = {}

# List of URLs to test for CORS misconfigurations
urls_to_test = {}
headers_to_test = {}

# List of URLs already tested for CORS misconfigurations
tested = []

# Session: python requests browser
session = requests.Session()

# CONSTANTS
DEBUG = True
SITE  = ''
MAX   = 10

# Regex to avoid requesting URLs that might cause a logout
LOGOUT_BLACKLIST_REGEX = re.compile(
    '(sign|log|opt)[+-_]*(out|off)|leave',
    re.IGNORECASE
)

USER_AGENT = f'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.11{random.randint(1, 9)} Safari/537.36'

BLACKLISTED_DOMAINS = [
    'doubleclick.net', 'googleadservices.com',
    'google-analytics.com', 'googletagmanager.com',
    'googletagservices.com', 'googleapis.com',
    'googlesyndication.com', 'analytics.ticktok.com',
    'gstatic.com',
]

# =============================================================================
# =============================================================================
# =================================== MAIN ====================================
# =============================================================================
# =============================================================================

if __name__ == '__main__':
    # Arguments parsing
    parser = argparse.ArgumentParser(prog='cors-oauth.py', description='CORS misconfiguraztions automated detection tool')

    parser.add_argument('-t', '--target',      required=False,       help='Target website')
    parser.add_argument('-S', '--stats',       default='stats',      help='Statistics folder')
    parser.add_argument('-R', '--reports',     default='reports',    help='Reports folder')
    parser.add_argument('-l', '--logs',        default='logs',       help='Logs folder')
    parser.add_argument('-L', '--links',                             help='File containing the login links')
    parser.add_argument('-u', '--url',                               help='Do not crawl the website, just test the given URL(s)')
    parser.add_argument('-m', '--max',         default=MAX,          help=f'Maximum number of URLs to crawl (Default: {MAX})')
    parser.add_argument('-v', '--variations',                        help=f'What variations to test for (Count from 1. e.g., "1-5" or "1,4")')
    parser.add_argument('-N', '--no-headless',                       help='Do not use a headless browser', action='store_true')
    parser.add_argument('-r', '--retest',                            help='Test already tested URLs', action='store_true')

    args = parser.parse_args()

    if args.url:
        c = 0
        _urls_to_test = {}
        for url in args.url.split(','):
            if url not in list(_urls_to_test.values()):
                if 'https://' not in url and 'http://' not in url:
                    url = 'https://' + url

                if 'www.' not in url:
                    _urls_to_test[f'test{c}'] = url
                    _urls_to_test[f'www_test{c}'] = \
                        url.replace('https://', 'https://www.').replace('http://', 'http://www.')
                else:
                    _urls_to_test[f'test{c}'] = url.replace('www.', '')
                    _urls_to_test[f'www_test{c}'] = url
                c += 1
        if args.target:
            SITE = (
                args.target
                .strip()
                .lower()
                .replace('http://',  '')
                .replace('https://', '')
                .replace('www.',    '')
            )
        else:
            SITE = urlparse(_urls_to_test['test0']).netloc.replace('www.', '')
    else:
        if args.links:
            with open(args.links, 'r') as f:
                file_links = json.load(f)
                SITE = file_links['site']
        elif args.target is None:
            log(f'Target website not specified')
            exit()
        else:
            SITE    = (
                args.target
                .strip()
                .lower()
                .replace('http://',  '')
                .replace('https://', '')
                .replace('www.', '')
            )

    statistics['site'] = SITE
    LOGS        = args.logs
    STATS       = args.stats
    REPORTS     = args.reports
    MAX         = int(args.max)
    HEADLESS    = not args.no_headless
    VARIATIONS  = []
    if args.variations:
        if ',' in args.variations:
            VARIATIONS = [int(i) for i in args.variations.split(',')]
        elif '-' in args.variations:
            VARIATIONS = range(
                int(args.variations.split('-')[0]),
                int(args.variations.split('-')[1]) + 1
            )
        else:
            VARIATIONS = [int(args.variations)]
        log(f'Only testing variation(s): {", ".join([str(i) for i in VARIATIONS])}')

    try:
        # Get dictionaries from the files
        get_dictionaries()
        if args.url:
            for url_type in _urls_to_test:
                if _urls_to_test[url_type] not in list(urls_to_test.values()):
                    urls_to_test[url_type] = _urls_to_test[url_type]

        # If the links file is provided: retrieve the links
        if args.links:
            for url_type in file_links:
                if url_type != 'site' and \
                    url_type not in list(urls_to_test.values()):
                    urls_to_test[url_type] = file_links[url_type]

        # Clean the queue and visited_urls dictionaries
        queue = {}
        visited_urls = {}

        # 1. Find the homepage
        homepage_response = ''
        if 'homepage' not in urls_to_test and args.url is None:
            log(f'Crawling the site to collect the URLs to test')

            # Visit the homepage and follow redirects
            if 'homepage' not in urls_to_test:
                log('Searching for the homepage')

                # TODO: dump in file, check if file is present before getting it again
                homepage_response = session.get(f'http://{SITE}/', timeout=30)
                url = homepage_response.url
                add_to_visited(url)

                homepage = url
                print(f'found: {homepage}')

            elif 'homepage' in urls_to_test:
                homepage = urls_to_test['homepage']

            urls_to_test['homepage'] = homepage

        # 2. Find the in the homepage login page
        if 'login' not in urls_to_test and \
                'homepage' in urls_to_test and \
                args.url is None:
            log('Searching for the login page')

            # Get links from the homepage
            if homepage_response != '':
                links = get_links(urls_to_test['homepage'], homepage_response.text, only_internal=True)

                login_url = get_login_url(links)
                if login_url != '':
                    urls_to_test['login'] = login_url
                    print(f'Found login page: {login_url}')
                for _url in links:
                    add_to_queue(_url)

        # 3. If login page not found in point 2: crawl the site
        while 'login' not in urls_to_test and should_continue() and args.url is None:
            url = get_url_from_queue()

            if LOGOUT_BLACKLIST_REGEX.search(url):
                continue

            response = session.get(url)
            add_to_visited(url)

            # Get links from the page
            urls = get_links(response.url, response.text, only_internal=True)

            login_url = get_login_url(urls)
            if login_url != '':
                urls_to_test['login'] = login_url

            for _url in urls:
                add_to_queue(_url)

            # Check if it's the login page
            if 'login' not in urls_to_test and is_login_page(response.url, response.text):
                urls_to_test['login'] = url
                print(f'Found login page: {url}')
                break

        if not 'login' in urls_to_test and args.url is None:
            print('Login page not found')

        log(f'Website crawled:\n{json.dumps(urls_to_test, indent=4)}')

        # Test the URLs for CORS misconfigurations
        _tested = [] # Needed when retest is used
        for url_type in urls_to_test:
            url = urls_to_test[url_type]
            if not url.startswith('http'):
                # This is the OAuth tag, so here I should go to the login page and click on the button?
                # print(f'{url_type}: {url} not tested because tag')
                continue

            if not args.retest and get_template_url(url) in tested:
                continue
            elif args.retest and get_template_url(url) in _tested:
                continue

            try:
                test_url(url, headers_to_test[url] if url in headers_to_test else {})
                tested.append(get_template_url(url))
                _tested.append(get_template_url(url))
            except (NewConnectionError, MaxRetryError, ConnectionError):
                debug(f'Cannot test {url}')
                pass
            except:
                debug(f'Error testing {url}')
                traceback.print_exc()

    except SystemExit as e:
        save_dictionaries(SITE, STATS, REPORTS, LOGS)
        sys.exit(e)
    except (SSLError, NewConnectionError, MaxRetryError, ConnectionError, ReadTimeoutError, ReadTimeout):
        save_dictionaries(SITE, STATS, REPORTS, LOGS)
        debug(f'{SITE} timed out', file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        save_dictionaries(SITE, STATS, REPORTS, LOGS)
        exit(0)
    except:
        save_dictionaries(SITE, STATS, REPORTS, LOGS)
        debug(traceback.format_exc(), file=sys.stderr)
        sys.exit(1)
    finally:
        save_dictionaries(SITE, STATS, REPORTS, LOGS)
        log(f'All done!')
        sys.exit(0)
