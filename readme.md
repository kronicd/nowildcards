# nowildcards

So you've got a big list of FQDNs from your passive dns, subdomain discovery, and certificate mining efforts, but 99% of them are from wildcard resolution?

Yes they could all be amazingly useful, but sometimes you really want to trim anything from wildcard resolution away.

This script does that for you.

## Usage

```bash
python3 nowildcard.py -h
usage: nowildcard.py [-h] [-v] [-t THREADS] [-c CHUNKSIZE] -o OUTPUT [-i ITERATIONS] [-T TIMEOUT] dnslist

positional arguments:
  dnslist               A text file containing a newline separated list of domain names

options:
  -h, --help            show this help message and exit
  -v, --verbose         use -v for normal verbosity, -vv for more verbosity, up to -vvvv
  -t THREADS, --threads THREADS
                        Number of threads
  -c CHUNKSIZE, --chunksize CHUNKSIZE
                        Work chunk size (the number of FQDNs allocated to each thread)
  -o OUTPUT, --output OUTPUT
                        Output file path
  -i ITERATIONS, --iterations ITERATIONS
                        Number of times to check each FQDN
  -T TIMEOUT, --timeout TIMEOUT
                        Timeout for DNS resolution in seconds
```

## Approach

For each FQDN in the input file
* Do not process FQDNs with invalid characters
* Do not process FQDNs with less than a single `.`
* Intelligently handle the TLD portion of the FQDN
* query (A and AAAA, follow CNAMES) the FQDN
* query (A and AAAA, follow CNAMES) an unlikely to resolve sibling FQDN
* compare result
* if they match, consider it a wildcard and ignore it
* if they don't match, consider it a standard resolution and output it

## Features

* Threading
* Exception handling
* Caching

## Limitations

Due to things like round-robin DNS and the occasional failure there will be false positives, that is, some wildcard FQDNs will make it into the output. It is recommended to re-run the process a few times on the output to clean up the false positives. Repeat until you are satisfied.
