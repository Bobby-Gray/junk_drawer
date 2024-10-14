import dns.query
import dns.resolver
import dns.zone
import json
from Levenshtein import distance
import re
import requests
import os
from pprint import pprint
import pyunycode
import tldextract
import whois

## Impersonation Domain Scanner Script
## This script scans the past 14 days of newly registered domains (NRDs) for pattern matches based on two user inputs, must and optional.
### The 'must' input will be required for every permutation while the 'optional' values will be considered before or after the 'must' values as optional matches.
### The script generates regex containing all potential 'confusable' characters then converts all NRD punycode where applicable. It also uses the original inputs to scan for levenshtein distance as domains are considered.
### Results are output to a dictionary then the script will attempt to resolve DNS a, nx, mx, registrar, and created_epoch records for the discovered domains.
### Final results are output to a json file titled, 'impersonation_domain_matches.json'.

must_input = input("Enter comma + space separated list of strings that must be included in your domain search. E.g., for account.google.com, google must be included.\n") 
opt_input = input("Enter comma + space separated list of optional strings to included in your domain search. E.g., for account.google.com, account or login or corporate are optional inclusions.\n (Default: ['account', 'activity', 'app', 'auth', 'cloud', 'corp', 'corporate', 'demo', 'duo', 'enterprise', 'gov', 'help', 'internal', 'login', 'mfa', 'okta', 'rsa', 'sign', 'signin', 'sso', 'support'])\n") or ['account', 'activity', 'app', 'auth', 'cloud', 'corp', 'corporate', 'demo', 'duo', 'enterprise', 'gov', 'help', 'internal', 'login', 'mfa', 'okta', 'rsa', 'sign', 'signin', 'sso', 'support', 'works']

if isinstance(must_input, str):
    must = must_input.split(', ')
if isinstance(must_input, list):
    must = must_input
if isinstance(opt_input, str):
    opt = opt_input.split(', ')
if isinstance(opt_input, list):
    opt = opt_input
print(f'must contain list: {must}')
print(f'optional contain list: {opt}')
ftd_url = 'https://raw.githubusercontent.com/xRuffKez/NRD/main/lists/14-day/domains-only/nrd-14day.txt'
confusables_url = 'https://raw.githubusercontent.com/gc/confusables/master/src/characters.ts'
ftd_filename = os.path.join(os.getcwd(), 'nrd_14day.txt')
confusables_filename = os.path.join(os.getcwd(), 'characters.ts')

def scrape_nrds(url, td_filename):
    print(f'Scraping domains registered in the past 14 days and checking for matches...')
    r_td = requests.get(url, stream=True)
    r_td.raise_for_status()  # Raise an exception for bad status codes
    with open(td_filename, "wb") as file:
        for chunk in r_td.iter_content(chunk_size=8192):
            file.write(chunk)

def build_impersonation_regex(must, opt, td_filename):
    print(f'Building impersonation domain match regex via confusables and punycode...')
    must_rex = ""
    pre_opt_rex = ""
    post_opt_rex = ""
    confusables = {}
    imp_domains_matches = {}
    ld_list = []
    ### Build levenshtein distance pattern combinations
    for mld in must:
        ld_list.append(mld)
        for old in opt:
            ld_list.append(old + mld)
            ld_list.append(mld + old)
    ### Pull confusables text file
    r_confusables = requests.get(confusables_url, stream=True)
    r_confusables.raise_for_status()  # Raise an exception for bad status codes
    with open(confusables_filename, "wb") as file:
        for chunk in r_confusables.iter_content(chunk_size=8192):
            file.write(chunk)
    with open(confusables_filename, "r") as file:
        lines = file.readlines()
        linecount = 0
        linestart = 0
        for i in lines:
            if '([' in str(i):
                linestart = linecount + 3
            linecount += 1
        pattern = r"'([^']*)', '([^']*)'"
        for i in range(linestart, linecount-1):
            match = re.search(pattern, lines[i])
            if match:
                val1 = str(match.group(1)) 
                val2 = str(match.group(2))
                confusables.update({val1: val2})
            else:
                continue
    ### Generate confusables character regex for 'must' list
    musts = []
    for md in must:
        ## Ex (([chars_1]){1}([chars_2]){1}([chars_3]){1})+
        must_rex_str = []
        for char in md:
            for k,v in confusables.items():
                if char == k:
                    must_rex_val = ""
                    must_rex_append = char
                    for conf_char in v:
                        must_rex_append = must_rex_append + conf_char
                    must_rex_val = "([" + must_rex_append + "]){1}"
                    must_rex_str.append(must_rex_val)
        if len(must_rex_str) > 0:
            musts.append(str("(" + "".join(must_rex_str) + ")"))
    if len(musts) > 1:
        must_rex = str("(" + "|".join(musts) + "+)")
    else:
        must_rex = "".join(musts) + "+"
    ### Generate confusables character regex for 'optional' list
    pre_opts = []
    post_opts = []
    for od in opt:
        opt_rex_str = []
        for char in od:
        ### Ex (((([cC]){1}([oO]){1}([rR]){1}([pP]){1})|(([aA]){1}([cC]){1}([cC]){1}([oO]){1}([uU]){1}([nN]){1}([tT]){1}))+|\n)
            for k,v in confusables.items():
                if char == k:
                    opt_rex_val = ""
                    opt_rex_append = char
                    for conf_char in v:
                        opt_rex_append = opt_rex_append + conf_char
                    opt_rex_val = "([" + opt_rex_append + "]){1}"
                    opt_rex_str.append(opt_rex_val)
        if len(opt_rex_str) > 0:
            pre_opts.append(str("(^" + "".join(opt_rex_str) + ")"))
            post_opts.append(str("(" + "".join(opt_rex_str) + "$)"))
    if len(pre_opts) > 1:
        pre_opt_rex = str("(" + "|".join(pre_opts) + "+|^)")
        post_opt_rex = str("(" + "|".join(post_opts) + "+|$)")
    else:
        pre_opt_rex = "".join(post_opts) + "|^"
        post_opt_rex = "".join(post_opts) + "|$"
    opt_must_opt = pre_opt_rex + must_rex + post_opt_rex
    ### Scan newly registered domains for matches
    RE_PATTERNS = re.compile(opt_must_opt) 
    with open(td_filename, "r") as file:
        lines = file.readlines()
        for i in lines:
            nrd_dom = tldextract.extract(str(i.strip())).domain
            nrd_subdom = tldextract.extract(str(i.strip())).subdomain
            if nrd_subdom:
                nrd_dom = nrd_subdom + nrd_dom
            ### Convert punycode where applicable
            try:     
                nrd_dom = pyunycode.convert(nrd_dom)
            except Exception as e:
                continue
            dn = str(i.strip())
            for ld in ld_list:
                if len(ld) > 4:
                    ld_match = distance(str(ld), str(nrd_dom))
                    if ld_match < 2:
                        print(dn)
                        if ld not in imp_domains_matches.keys():
                            imp_domains_matches.update({ld : {'result' : []}})
                        ld_fuzzer = 'levenshtein_distance_' + str(ld_match)
                        imp_domains_matches[ld]['result'] += [{
                            'fuzzer': str(ld_fuzzer),
                            'domain': str(dn),
                            'dns_ns': [],
                            'dns_a': [],
                            'dns_mx': [],
                            'registrar': '',
                            'created_epoch': ''
                            }]
            match = RE_PATTERNS.search(nrd_dom)
            if match:
                matched = match.group()
                if matched not in imp_domains_matches.keys():
                    imp_domains_matches.update({matched : {'result' : []}})
                print(dn)
                re_in_dn_fuzzer = 'imp_domain_rex_match'
                imp_domains_matches[matched]['result'] += [{
                    'fuzzer': str(re_in_dn_fuzzer),
                    'domain': str(dn),
                    'dns_ns': [],
                    'dns_a': [],
                    'dns_mx': [],
                    'registrar': '',
                    'created_epoch': ''
                    }]
    # Loop through results and attempt to fill any missing dns context
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '2001:4860:4860::8888', '8.8.4.4', '2001:4860:4860::8844']
    for key, value_list in imp_domains_matches.items():
        for item in value_list['result']:
            # Check if 'registrar' is empty or None 
            item_domain = item['domain']
            try:
                if not item['registrar'] or not item['created_epoch']:  
                    try:
                        w = whois.whois(item_domain)
                        registrar = w.registrar
                        creation_date = w.creation_date
                        if registrar:
                            item['registrar'] = registrar
                        if creation_date:
                            if isinstance(w.creation_date, list): 
                                created_epoch = w.creation_date[0].strftime('%s')
                            else:
                                created_epoch = w.creation_date.strftime('%s')
                            item['created_epoch'] = created_epoch
                    except Exception as e:
                        print(f'{item_domain} failed whois lookup w/ {e}')
                if not item['dns_ns']:  
                    try:
                        ns = resolver.resolve(item_domain, 'NS')
                        if ns:
                            ns_j = [s.to_text() for s in ns]
                            item['dns_ns'] = ns_j
                    except Exception as e:
                        print(f'{item_domain} failed dns ns lookup w/ {e}')
                if not item['dns_a']:  
                    try:
                        ar = resolver.resolve(item_domain, 'A')
                        if ar:
                            ar_j = [a.to_text() for a in ar]
                            item['dns_a'] = ar_j
                    except Exception as e:
                        print(f'{item_domain} failed dns a lookup w/ {e}')
                if not item['dns_mx']:  
                    try:
                        mx = resolver.resolve(item_domain, 'MX')
                        if mx:
                            mx_j = [rdata.exchange.to_text() for rdata in mx]
                            item['dns_mx'] = mx_j
                    except Exception as e:
                        print(f'{item_domain} failed dns mx lookup w/ {e}')
            except Exception as e:
                print(f'{item_domain} failed dns context lookup w/ {e}')
    with open(os.path.join(os.getcwd(), "impersonation_domain_matches.json"), "w") as outfile:
        json.dump(imp_domains_matches, outfile, indent=4, sort_keys=True)
    pprint(f'Impersonation domains discovered: {imp_domains_matches}')
    return imp_domains_matches


if __name__=="__main__":
    imp_domains = build_impersonation_regex(must, opt, ftd_filename)
