#!/usr/bin/env python3

from concurrent.futures import ThreadPoolExecutor
import threading
from contextlib import contextmanager
from pprint import pprint
import argparse
import dns.resolver
import re
import tldextract
import itertools
import sys
import time
import random

parser = argparse.ArgumentParser()
parser.add_argument("dnslist", help="A text file containing a newline separated list of domain names")
parser.add_argument("-v", "--verbose", default=0, action="count", help="use -v for normal verbosity, -vv for more verbosity, up to -vvvv")
parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
parser.add_argument("-c", "--chunksize", type=int, default=20, help="Work chunk size (the number of FQDNs allocated to each thread)")
parser.add_argument("-o", "--output", type=str, required=True, help="Output file path")
parser.add_argument("-i", "--iterations", type=int, default=1, help="Number of times to check each FQDN")
parser.add_argument("-T", "--timeout", type=float, default=2.0, help="Timeout for DNS resolution in seconds")
args = parser.parse_args()

TEST_PREFIX = "this_should_not_exist_lkjhgfdsazxcvbnm"
DNS_RESOLVERS = ['209.244.0.3', '209.244.0.4', '8.8.8.8', '8.8.4.4', '208.67.222.222', '208.67.220.220', '1.1.1.1']  # Add more if needed
MAX_FQDNS_PER_THREAD = args.chunksize

stdio_lock = threading.Lock()
cache_lock = threading.Lock()
output_lock =threading.Lock() 
stats_lock = threading.Lock()
cache = {}

fqdns_processed_count = 0
start_time = time.time()

def print_debug(output, level):
    if args.verbose >= level:
        with stdio_lock:
            sys.stderr.write(f"{output}\n")
            sys.stderr.flush()

def search_cache(fqdn):
    if fqdn in cache:
        print_debug(f'[*] Cache hit for {fqdn}', 4)
        return cache.get(fqdn)
    else:
        print_debug(f'[*] Cache miss for {fqdn}', 4)
        return None

def update_cache(fqdn, result):
    with cache_lock:
        cache.update({fqdn:result})

def is_valid_fqdn(fqdn):
    # a very lazy check, only eliminates input with invalid characters
    fqdn_pattern = re.compile(r"^(?!-)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$")
    return bool(fqdn_pattern.match(fqdn))

def resolve_fqdn(fqdn):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = random.sample(DNS_RESOLVERS, len(DNS_RESOLVERS))

    if fqdn.startswith(f'{TEST_PREFIX}.'):
        if search_cache(fqdn):
            return search_cache(fqdn)

    ipv4_addresses = set()
    ipv6_addresses = set()

    # Resolve IPv4 addresses
    try:
        answers_ipv4 = resolver.resolve(fqdn, 'A')
        ipv4_addresses = {rdata.address for rdata in answers_ipv4}
    except dns.resolver.NoAnswer:
        #print_debug(f'[-] No answer for {fqdn}', 3)
        pass
    except dns.resolver.NXDOMAIN:
        # print_debug(f'[-] NXDOMAIN for {fqdn}', 3)
        pass
    except Exception as e:
        print_debug(f'[*] Resolution failed {e}', 1)
        #pass

    # Resolve IPv6 addresses
    try:
        answers_ipv6 = resolver.resolve(fqdn, 'AAAA')
        ipv6_addresses = {rdata.address for rdata in answers_ipv6}
    except dns.resolver.NoAnswer:
        #print_debug(f'[-] No answer for {fqdn}', 3)
        pass
    except dns.resolver.NXDOMAIN:
        # print_debug(f'[-] NXDOMAIN for {fqdn}', 3)
        pass
    except Exception as e:
        print_debug(f'[*] Resolution failed {e}', 1)
        #pass

    ip_addresses = ipv4_addresses.union(ipv6_addresses)

    if not ip_addresses:
        print_debug(f'[-] Could not resolve domain {fqdn}', 3)
    else:
        print_debug(f'[+] FQDN {fqdn}, IP: {str(ip_addresses)}', 3)

    update_cache(fqdn, ip_addresses)

    return ip_addresses

def check_fqdn_for_wildcard(fqdn, iterations = 1):
    extracted = tldextract.extract(fqdn)
    domain = extracted.domain
    suffix = extracted.suffix
    fqdn_no_suffix = f'{extracted}.{domain}'

    if "." in fqdn_no_suffix:
        try:
            fqdn_level_up = fqdn.split(".", 1)[1]
        except Exception as e:
            print_debug(f'[-] Exception fired on {fqdn}: {e}', 1)
            return None

        for i in range(0, iterations, 1):
            # check for wildcards if needed
            test_fqdn = f'{TEST_PREFIX}.{fqdn_level_up}'
            if resolve_fqdn(fqdn).difference(resolve_fqdn(test_fqdn)):
                update_cache(fqdn_level_up, False)
                print_debug(f'[-] Is not wildcard: {fqdn} check: {i+1}/{iterations}', 2)
                if i == iterations-1:
                    return False
            else:
                update_cache(fqdn_level_up, True)
                print_debug(f'[-] Wildcard (or non-exist) detected: {fqdn}', 2)
                return True

    else:
        return None

def process_fqdns(fqdns_chunk):
    global fqdns_processed_count
    thread_id = threading.get_ident()
    print_debug(f'[*] Thread {thread_id} processing {len(fqdns_chunk)} fqdns', 1)

    results = {}
    for fqdn in fqdns_chunk:
        fqdn = fqdn.strip()
        result = check_fqdn_for_wildcard(fqdn, args.iterations)
        results[fqdn] = result
        with stats_lock:
            print_debug(f'[*] Thread {thread_id} processed count {fqdns_processed_count}', 4)
            fqdns_processed_count += 1

    # Count the number of True (W) and False (S) results
    true_count = sum(1 for value in results.values() if value)
    false_count = len(results) - true_count

    end_time = time.time()
    elapsed_time = end_time - start_time
    fqdns_per_second = fqdns_processed_count / elapsed_time

    print_debug(f'[*] Thread {thread_id} exiting {len(results)} fqdns (W: {true_count} S: {false_count})', 1)
    print_debug(f'[*] Rate of FQDN processing (p/s): {fqdns_per_second:.2f}', 0)

    return results, thread_id  # Return the thread ID along with results


if __name__ == "__main__":
    fqdns_generator = (line.rstrip('\n') for line in open(args.dnslist))

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        thread_results = []  # List to collect thread results and IDs
        while True:
            fqdns_chunk = list(itertools.islice(fqdns_generator, MAX_FQDNS_PER_THREAD))
            if not fqdns_chunk:
                break  # Break the loop if no more FQDNs to process
            result = executor.submit(process_fqdns, fqdns_chunk)
            thread_results.append(result)

        non_wildcard_output_file = args.output

        for result in thread_results:
            results, thread_id = result.result()
            for fqdn, is_wildcard in results.items():
                if is_wildcard is True or is_wildcard is None:
                    #print(f'[-] WILDCARD: {fqdn} | value {is_wildcard}')
                    pass
                else:
                    print_debug(f'[+] STANDARD: {fqdn}', 1)
                    # Save non-wildcards to the text file
                    with output_lock:
                        with open(args.output, 'a') as output:
                            output.write(f'{fqdn}\n')
