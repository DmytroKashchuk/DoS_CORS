#!/usr/bin/env python3

from ast import List
import os
import json
import requests
import wcde
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs
from colorama import Fore, Back, Style
import random
import string
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl
import corsoauth
from colorama import Fore, Style
import sys
import art
import argparse

# =============================================================================
# =============================================================================
# ============================== GLOBAL VARIABLES =============================
# =============================================================================
# =============================================================================
stats_folder_path = "stats"
report_folder_path = "reports"
vulnerable_sites_header_heuristics = {}
vulnerable_sites_acao_check = {}
vulnerable_sites_vary_origin = {}
USER_AGENT = f'Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.11{random.randint(1, 9)} Safari/537.36'

vulnerable_sites_header_heuristics = {}
vulnerable_sites_acao_check = {}
vulnerable_sites_vary_origin = {}
summaries = []
websites_stats = {}
statistics_websites = []

total_websites = 0
total_cors_websites = 0
total_cors_vulnerable_websites = 0
errors = []
end_match = []


# =============================================================================
# =============================================================================
# ================================ STATISTICS =================================
# =============================================================================
# =============================================================================

class summary:
    def __init__(self, websitename, vulnerable_sites_header_heuristics=[], vulnerable_sites_acao_check=[], vulnerable_sites_vary_origin=[]):
        self.websitename = websitename
        self.vulnerable_sites_header_heuristics = vulnerable_sites_header_heuristics
        self.vulnerable_sites_acao_check = vulnerable_sites_acao_check
        self.vulnerable_sites_vary_origin = vulnerable_sites_vary_origin
    
    def print_summary(self):
        print(f'Website: {self.websitename}')
        print(f'Vulnerable sites header heuristics: {len(self.vulnerable_sites_header_heuristics)}')
        print(f'Vulnerable sites ACAO check: {len(self.vulnerable_sites_acao_check)}')
        print(f'Vulnerable sites Vary: {len(self.vulnerable_sites_vary_origin)}')
        print(f'Total vulnerable sites: {len(self.vulnerable_sites_header_heuristics) + len(self.vulnerable_sites_acao_check) + len(self.vulnerable_sites_vary_origin)}')

def add_new_summary(websitename, vulnerable_sites_header_heuristics=[], vulnerable_sites_acao_check=[], vulnerable_sites_vary_origin=[]):
    summary_object = summary(websitename, vulnerable_sites_header_heuristics, vulnerable_sites_acao_check, vulnerable_sites_vary_origin)
    summary_object.print_summary()
    return summary_object

def create_summaries_file():
    with open('summary.json', 'w') as f:
        json.dump(summaries, f, indent=4)

def create_summary_file(summary):
    with open(f'summaries/summary_{summary.websitename}.json', 'w') as f:
        json.dump(summary, f, indent=4)

class Website:
    def __init__(self, website_number, website_url, website_redirected_url, url_vulnerability,
                 first_request_headers, first_response_headers,
                 is_first_request_coming_from_cache, second_request_headers,
                 second_response_headers, is_second_request_coming_from_cache, vulnerable, acao_equal_origin):
        self.website_number = website_number
        self.website_url = website_url
        self.website_redirected_url = website_redirected_url
        self.url_vulnerability = url_vulnerability
        self.first_request_headers = first_request_headers
        self.first_response_headers = first_response_headers
        self.is_first_request_coming_from_cache = is_first_request_coming_from_cache
        self.second_request_headers = second_request_headers
        self.second_response_headers = second_response_headers
        self.is_second_request_coming_from_cache = is_second_request_coming_from_cache
        self.vulnerable = vulnerable
        self.acao_equal_origin = acao_equal_origin

def add_website(website_number, website_url, website_redirected_url, url_vulnerability,
                first_request_headers, first_response_headers,
                is_first_request_coming_from_cache, second_request_headers,
                second_response_headers, is_second_request_coming_from_cache, vulnerable, acao_equal_origin):
    website = Website(website_number, website_url, website_redirected_url, url_vulnerability,
                      first_request_headers, first_response_headers,
                      is_first_request_coming_from_cache, second_request_headers,
                      second_response_headers, is_second_request_coming_from_cache, vulnerable, acao_equal_origin)
    statistics_websites.append(website)
    return website

def create_json_file(filename, vulnerabilities_list):
    website_list = []
    for website in vulnerabilities_list:
        website_dict = {
            'website_domain_name': website.website_url,
            'Vulnerable_URL': website.url_vulnerability,
            'Tested_Vulnerability': website.vulnerable,
            'acao_equal_origin': website.acao_equal_origin,
            'is_first_request_coming_from_cache': website.is_first_request_coming_from_cache,
            'is_second_request_coming_from_cache': website.is_second_request_coming_from_cache,
            'first_request_headers': website.first_request_headers,
            'first_response_headers': website.first_response_headers,            
            'second_request_headers': website.second_request_headers,
            'second_response_headers': website.second_response_headers,
        }
        website_list.append(website_dict)
    with open(filename, 'w') as f:
        json.dump(website_list, f)

def print_website(website):
    print(Fore.YELLOW + "Website number:", website.website_number)
    print("Website URL:", website.website_url)
    print("Website redirected URL:", website.website_redirected_url)
    print("URL vulnerability:", website.url_vulnerability)
    print(Fore.CYAN + "First request headers:")
    print(Style.BRIGHT + json.dumps(website.first_request_headers, indent=4))
    print(Fore.CYAN + "First response headers:")
    print(Style.BRIGHT + json.dumps(website.first_response_headers, indent=4))
    print("Is first request coming from cache:", website.is_first_request_coming_from_cache)
    print(Fore.CYAN + "Second request headers:")
    print(Style.BRIGHT + json.dumps(website.second_request_headers, indent=4))
    print(Fore.CYAN + "Second response headers:")
    print(Style.BRIGHT + json.dumps(website.second_response_headers, indent=4))
    print("Is second request coming from cache:", website.is_second_request_coming_from_cache)
    print("Vulnerable:", website.vulnerable)
    print("ACAO equal origin:", website.acao_equal_origin)
    print(Style.RESET_ALL)

def print_website_info(website):
    first_req = website.is_first_request_coming_from_cache
    url = website.website_url
    second_req = website.is_second_request_coming_from_cache
    vulnerable = website.vulnerable
    acao_equal_origin = website.acao_equal_origin
    first_origin = website.first_request_headers.get('Origin', None)
    second_origin = website.second_request_headers.get('Origin', None)
    first_acao = website.first_response_headers.get('Access-Control-Allow-Origin', None)
    second_acao = website.second_response_headers.get('Access-Control-Allow-Origin', None)
    print(f" first_req: {first_req} url: {url} second_req: {second_req} vulnerable: {vulnerable} acao_equal_origin: {acao_equal_origin} first_origin: {first_origin} second_origin: {second_origin} first_acao: {first_acao} second_acao: {second_acao}")
    print("\r\r\r")

def extract_info_from_stats(json_file):
    '''
    Once opened json file ([website]-statistics.json) from stats folder
    this function extracts the site, cors and vulnerable values from the json file
    '''
    with open(json_file, 'r') as f:
        data = json.load(f)
        site = data.get('site', None)
        cors = data.get('cors', None)
        variations = data.get('variations', None)
        vuln_urls = data.get('vulnerable_urls', None)
        return site, cors, variations, vuln_urls

def get_cors_webistes():
    '''
    This function accesses the stats folder opens all the json files
    and checks if the website has cors enabled, if so it adds the website to the 
    cors_true_websites list and return the list
    '''
    cors_true_websites = []
    for file_name in os.listdir(stats_folder_path):
        if file_name.endswith('.json'):
            json_path = os.path.join(stats_folder_path, file_name)
            site, cors, vulnerable, vuln_urls = extract_info_from_stats(json_path)
            if cors:
                cors_true_websites.append(site)

    return cors_true_websites

def get_redirected_url(json_file):
    '''
    this function gets the last redirect url from the report folder using
    the [webiste]-report.json json
    '''
    with open(json_file, 'r') as file:
        data = json.load(file)
    
    return list(data.keys())[0]

def get_vulnerabilities(file_name):
    '''
    This function extracts vulnerable websites from the statistics file
    '''
    json_path = os.path.join(stats_folder_path, file_name)
    site, cors, vulnerable, vuln_urls = extract_info_from_stats(json_path)

    return vulnerable

def cache_busting(url):
    """
    Adds a cache-busting query parameter to the given URL, considering
    any existing query parameters and fragments.
    """
    parsed_url = urlparse(url)

    # Generate a cache-busting random string
    cache_busting_param = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

    # Parse existing query parameters and add the cache-busting parameter
    query_params = parse_qsl(parsed_url.query)
    query_params.append(('cachebuster', cache_busting_param))

    # Reconstruct the URL with the new cache-busting query parameter
    modified_url = urlunparse(
        (parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params,
         urlencode(query_params), parsed_url.fragment)
    )

    return modified_url

def cache_busting_v2(url):
    """
    Adds a cache-busting path segment to the given URL, considering
    any existing query parameters and fragments.
    """
    parsed_url = urlparse(url)

    # Generate a cache-busting random string
    cache_busting_param = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

    # Add the cache-busting path segment to the existing path
    modified_path = f"{parsed_url.path.rstrip('/')}/cachebuster/{cache_busting_param}"

    # Reconstruct the URL with the new cache-busting path segment
    modified_url = urlunparse(
        (parsed_url.scheme, parsed_url.netloc, modified_path, parsed_url.params,
         parsed_url.query, parsed_url.fragment)
    )

    return modified_url

def fetch_headers(url, origin):
    ''' 
    This function takes the url and origin and returns the headers of GET request
    '''
    headers1 = {
            'Origin': origin,
            'User-Agent': USER_AGENT,
    }

    response = requests.get(url, headers=headers1, timeout=5)
    return response

def find_report_file(domain, directory_path):
    '''
    This function takes the website domain and returns
    the [website]-report.json file name which will be used to extract the
    redirected url
    '''
    report_file_name = f"{domain}-report.json"
    print(f"{Fore.RED}report_file_name: {report_file_name} {Style.RESET_ALL}")
    report_file_path = os.path.join(report_folder_path, report_file_name)
    if os.path.exists(report_file_path):
        return report_file_name
    else:
        return None

def check_vulnerability_header_heuristic(siteurl):
    '''
    This function checks if the website is vulnerable to CORS DoS
    using the header heuristics method
    '''
    if wcde1=="MISS" and wcde2=="HIT":
        vulnerable_sites_header_heuristics[siteurl] = vuln
        return True
    else:
        return False

def check_vulnerability_acao(header2, siteurl, origin):
    '''
    This function checks if the website is vulnerable to CORS DoS
    using the ACAO check method: compares if the ACAO header of the second response
    is equal to the origin header of the first request
    '''
    acao = header2.get('Access-Control-Allow-Origin')

    if acao==origin:
        vulnerable_sites_acao_check[siteurl] = vuln
        return True
    else:
        return False

def is_origin_in_vary(header2, siteurl, vuln):
    '''
    checks if the website is vulnerable to CORS DoS using the Vary header
    checking if origin is in the Vary header
    '''    
    vary = header2.get('Vary')

    if vary=="Origin":
        vulnerable_sites_vary_origin[siteurl] = vuln
        return True
    else:
        return False

def print_dictionary(dictionary):

    if dictionary == {}: 
        print("[No vulnerbale web sites found]")
    else:
        for key, value in dictionary.items():
            print(f" CORS {Fore.RED} {key} {Style.RESET_ALL} misconfiguration found in {Fore.BLUE} {value} {Style.RESET_ALL}")

def get_vuln_urls(file_name):
    json_path = os.path.join(stats_folder_path, file_name)
    site, cors, vulnerable, vuln_urls = extract_info_from_stats(json_path)

    return vuln_urls

def create_statistic_for_website(x, websites):
    directory = "results"
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"The directory {directory} did not exist and has been created.")
    name = x.replace(":", "")
    create_json_file("results/" +name + "-report.json", websites)

def get_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if not domain.startswith('www.'):
        domain = 'www.' + domain
    return parsed_url.scheme + '://' + domain

def create_summary_file(sites_heuristics, sites_acao):
    print(f"{Fore.GREEN}[+] Creating 'summary.json' file...{Style.RESET_ALL}")
    filename = "summary.json"
    website_list = []
    website_dict = {
        'Vulnerable_Heuristically': sites_heuristics,
        'Vulnerable_ACAO': sites_acao,
        'is_origin_in_vary': vulnerable_sites_vary_origin
    }
    website_list.append(website_dict)
    with open(filename, 'w') as f:
        json.dump(website_list, f)

def print_progress_bar(count, total):
    percent_complete = (count / total) * 100
    sys.stdout.write(f'\rProgress: {percent_complete:.2f}% ({count}/{total})\r')
    sys.stdout.flush()

def check_directories():
    directories = ["reports", "logs", "stats"]
    return all(os.path.isdir(directory) for directory in directories)

if __name__ == '__main__':
    
    if check_directories():

        origin = "https://default.com"
        origin2 = "https://web.defaultpage.com"
        count = 0
        cors_true_websites = get_cors_webistes()
        
        files = os.listdir("results")
        
        for website in cors_true_websites:
            
            try:
                count += 1
                print_progress_bar(count-1, len(cors_true_websites))
                print("\r\r")
                print(f"{Fore.GREEN}CHECKING: {website} {Style.RESET_ALL}")
                #find the report file of the website
                report_file_name = find_report_file(website, 'reports')
                
                urlf = get_redirected_url("reports/" + report_file_name) #extracted url from report file
                print(f"Redirected URL: {urlf}")

                #extract vulnerabilities of related to the website from statistics file
                vuln_urls = get_vulnerabilities(website + "-statistics.json")
                vulnerable_urls = get_vuln_urls(website + "-statistics.json")

                print(f"Vulnerabilities found: {vuln_urls}")
                
                if vulnerable_urls:
                    temp = []
                    temp_websitename = website
                    temp_vulnerable_sites_header_heuristics = []
                    temp_vulnerable_sites_acao_check = []
                    temp_vulnerable_sites_vary_origin = []         

                    for url, vulnerabilities in vulnerable_urls.items():
                        temp = []
                        count += 1
                        for vuln in vulnerabilities:
                            
                            try:
                                if vuln == "end_matching": 
                                    end_match.append(url)
                                print(f"{Fore.LIGHTMAGENTA_EX}[Testing] {website} with for: {vuln} Vulnerability {Style.RESET_ALL}")
                                #generate variations of the found vulnerablity
                                origin_variation = corsoauth.generate_variations(get_domain(url))
                                #==========PREPARE THE FIRST REQUEST===========
                                #create new origin base on the vulnerability
                                origin = origin_variation[vuln]
                                print(Fore.RED + f"Setting New Origin for first request: {origin} for {vuln}" + Style.RESET_ALL)

                                #create new url with cache busting query parameter
                                cburl = cache_busting(url)
                                print(f"Cache busting url: {cburl}")
                                
                                header1 = fetch_headers(cburl, origin)

                                print(f"Send the First GET request to url: {Fore.CYAN}{cburl} with Origin: {Fore.GREEN}{origin} {Style.RESET_ALL}")
                                wcde1 = wcde.cache_headers_heuristics(header1.headers)
                                print(f"Checking if the FIRST reposponse is coming from cache -------->: {wcde1}")
                                if wcde1=="HIT":
                                    #if the first response in HIT that the response is coming from cache
                                    #with is impossible with cache busting so try again with cache busting v2
                                    #that puts the cache busting parameter as a query parameter
                                    cburl = cache_busting_v2(url)
                                    header1 = fetch_headers(cburl, origin)
                                    wcde1 = wcde.cache_headers_heuristics(header1.headers)

                                #==========PREPARE THE SECOND REQUEST===========
                                #create new origin different from the first one based on the vulnerability
                                origin_variation = corsoauth.generate_variations(get_domain(url))
                                origin2 = origin_variation[vuln]
                                #---------Send the SECOND request and check if the response is coming from cache---------
                                print(Fore.RED + f"Setting New Origin for second request: {origin}" + Style.RESET_ALL)    
                                header2 = fetch_headers(cburl, get_domain(url))
                                print(f"{Fore.CYAN}Send the Second GET request to url: {cburl} with Origin: {origin} {Style.RESET_ALL}")
                                wcde2 = wcde.cache_headers_heuristics(header2.headers)

                                #print the summary of the requests
                                print(f"Checking if the SECOND reposponse is coming from cache -------->: {wcde2}")
                                print(f"{Fore.RED}First origin = {origin}, Second Origin = {origin2}, ACAO = {header2.headers.get('Access-Control-Allow-Origin')}" + Style.RESET_ALL)
                                print(f"\r\r\r")

                                #check if the website is vulnerable to the vulnerability using heuristics method and ACAO method
                                heuristcs = check_vulnerability_header_heuristic(cburl)
                                acao = check_vulnerability_acao(header2.headers, cburl, origin)
                                is_origin_in_vary(header2.headers, cburl, vuln)

                                #website_number, website_url, website_redirected_url, url_vulnerability,first_request_headers, first_response_headers, 
                                #is_first_request_coming_from_cache, second_request_headers,
                                #second_response_headers, is_second_request_coming_from_cache, vulnerable_to, acao_equal_origin
                                
                                #creating lists for statistics
                                temp.append(add_website(str(1), website, cburl, cburl,
                                            dict(header1.request.headers), dict(header1.headers),
                                            wcde1, dict(header2.request.headers), dict(header2.headers),
                                            wcde2,vuln,acao))
                                
                                #create summary for the website
                                #strucutre of summary: websitename, vulnerable_sites_header_heuristics=[], vulnerable_sites_acao_check=[], vulnerable_sites_vary_origin=[]
                                                        
                                summary_temp = add_new_summary('https://www.google.com', ['https://www.google.com'], ['https://www.google.com'], ['https://www.google.com'])
                                summaries.append(summary_temp)
                            except Exception as e:
                                print(f"Error: {e} for website: {website} and origin: {origin} trying {vuln} vulnerability")
                                errors.append((website, origin, vuln))
                        create_statistic_for_website(website, temp)
                        websites_stats[website] = temp
            except Exception as e:
                print(f"Error: {e} for website: {website}")
    else:
        print(f"{Fore.RED}[-] Please run the corsoauth.py script first to generate the reports, logs and stats folders {Style.RESET_ALL}")
        sys.exit(1)
            

    # Generate ASCII art for "THE END"
    ascii_art = art.text2art("THE END")

    # Print the ASCII art
    print(ascii_art)

    #print that the program is finished
    print(f"{Fore.GREEN}===========================================")
    print(f"Finished analyzing {len(cors_true_websites)} websites")
    print(f"{Fore.GREEN}===========================================\n" + Style.RESET_ALL)


    print(f"{Fore.RED}\r\rVulnerable WebSites: " + Style.RESET_ALL)
    print_dictionary(vulnerable_sites_acao_check)

    print(f"\n{Fore.GREEN}===========================================")
    print(f"total cors wesites analyzed = {len(cors_true_websites)}")
    print(f"total cors ACAO vulnerable websites = {len(vulnerable_sites_acao_check)}")
    print(f"total errors = {len(errors)}")
    print(f"{Fore.GREEN}===========================================\n" + Style.RESET_ALL)

    #========================Save the results to a file===========================

    #print statistics_websites
    '''
    for stat in statistics_websites:
        print_website(stat)

    for stat in statistics_websites:
        print_website_info(stat)
    '''
    #print errors
    for website, origin, vuln in errors:
        print(f"{Fore.RED}Error: {website} : {origin} : {vuln}{Style.RESET_ALL}")

    print("\n")
    #create summary.json file
    create_summary_file(vulnerable_sites_header_heuristics, vulnerable_sites_acao_check)