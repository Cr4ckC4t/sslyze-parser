#!/usr/bin/env python3

__version__ = '1.2.0'
__author__  = 'crackcat'
__license__ = 'wtfpl'

from sys import argv, exit
from sslyze import SslyzeOutputAsJson, ServerScanStatusEnum
import os.path
import requests
import argparse

SUCC	= 0x0
ERR	= 0x1

api_cache = {}

class fc:
	# Foreground color
	black = '\u001b[30m'
	red = '\u001b[31m'
	green = '\u001b[32m'
	orange = '\u001b[33m'
	blue = '\u001b[34m'
	magenta = '\u001b[35m'
	cyan = '\u001b[36m'
	b_red = '\u001b[41m'
	b_green = '\u001b[42m'
	b_orange = '\u001b[43m'
	b_blue = '\u001b[44m'
	end = '\u001b[0m'

def checkInternet():
	try:
		r = requests.get('https://8.8.8.8/')
		if r.status_code == 200:
			return True
		else:
			return False
	except:
		return False

def getCipherSuiteDetails(cipher_suite):
	global api_cache

	if cipher_suite in api_cache:
		return api_cache[cipher_suite]

	response = requests.get(f'https://ciphersuite.info/api/cs/{cipher_suite}')

	if ((c:=response.status_code) != 200):
		print(f'API request failed with: {c}')
		print(f'The ciphersuite.info API appears to be unavailable right now. Aborting.')
		exit(ERR)

	response = response.json()
	try:
		security = response[cipher_suite]['security']
		openssl_name = response[cipher_suite]['openssl_name']
		if security not in ['weak', 'secure', 'insecure', 'recommended']:
			print(f'The security level: {security} must be new. Add a handler for it and try again.')
			exit(ERR)
		api_cache[cipher_suite] = {'sec': security, 'openssl_name': openssl_name}
	except:
		print(f'The following cipher suite generated an unexpected API response: {cipher_suite}')
		print(f'Aborting.')
		exit(ERR)

	return api_cache[cipher_suite]

def main(sslyze_file, use_openssl_names, outfile):
	with open(sslyze_file) as f:
		ssl_json = f.read()

	try:
		parsed_results = SslyzeOutputAsJson.model_validate_json(ssl_json)
	except:
		print(f'Failed to parse {sslyze_file}.')
		print(f'Did you run sslyze with --json <outfile>?')
		exit(ERR)

	if not len(parsed_results.server_scan_results):
		print(f'It appears that no host was scanned successfully. Aborting.')
		exit(ERR)

	all_weak_ciphers = set()
	for server in parsed_results.server_scan_results:
		print(f'='*0x40)
		print(f'Host: {server.server_location.hostname}:{server.server_location.port}')

		if server.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            		print(f"Scan failed. Ignoring this host.")
            		continue

		scan_result = server.scan_result

		supported_suites = []
		supported_suites.extend(s3:=scan_result.ssl_3_0_cipher_suites.result.accepted_cipher_suites)
		supported_suites.extend(s2:=scan_result.ssl_2_0_cipher_suites.result.accepted_cipher_suites)
		supported_suites.extend(t10:=scan_result.tls_1_0_cipher_suites.result.accepted_cipher_suites)
		supported_suites.extend(t11:=scan_result.tls_1_1_cipher_suites.result.accepted_cipher_suites)
		supported_suites.extend(t12:=scan_result.tls_1_2_cipher_suites.result.accepted_cipher_suites)
		supported_suites.extend(t13:=scan_result.tls_1_3_cipher_suites.result.accepted_cipher_suites)

		total = len(supported_suites)
		groups = {
			'weak': [],
			'secure': [],
			'insecure': [],
			'recommended': []
		}

		print(f'Protocols: ', end="")
		n = 0
		if len(s2):
			print(f'{fc.red}SSL 2.0{fc.end}', end='')
			n+=1
		if len(s3):
			print(f'{", " if n else ""}{fc.red}SSL 3.0{fc.end}', end='')
			n+=1
		if len(t10):
			print(f'{", " if n else ""}{fc.red}TLS 1.0{fc.end}', end='')
			n+=1
		if len(t11):
			print(f'{", " if n else ""}{fc.red}TLS 1.1{fc.end}', end='')
			n+=1
		if len(t12):
			print(f'{", " if n else ""}{fc.green}TLS 1.2{fc.end}', end='')
			n+=1
		if len(t13):
			print(f'{", " if n else ""}{fc.green}TLS 1.3{fc.end}', end='')
		print()

		n = 0
		for suite in supported_suites:
			n+=1
			suite_id = suite.cipher_suite.name
			details = getCipherSuiteDetails(suite_id)
			sec = details['sec']
			if use_openssl_names:
				if len(details['openssl_name']):
					suite_id = details['openssl_name']
				else:
					suite_id += f' {fc.orange}(no OpenSSL name available){fc.end}'
			if outfile:
				if sec in ['weak', 'insecure']:
					all_weak_ciphers.add(suite_id)

			groups[sec].append(suite_id)

			li = len(groups['insecure'])
			lw = len(groups['weak'])
			ls = len(groups['secure'])
			lr = len(groups['recommended'])

			max = 50
			iblob = f'{fc.red}'+'█'*int(li/total*max)
			wblob = f'{fc.orange}'+'█'*int(lw/total*max)
			sblob = f'{fc.cyan}'+'█'*int(ls/total*max)
			rblob = f'{fc.green}'+'█'*int(lr/total*max)
			print(f'Ciphers: {n} |{iblob}{wblob}{sblob}{rblob}{fc.end}|', end='\r')
		print()
		print(f'-'*0x40)

		if (li):
			print(f'{fc.red}[X] Insecure ciphers ({li}|{total}):{fc.end}')
			for cs in groups['insecure']:
				print(f'\t{cs}')

		if (lw):
			print(f'{fc.orange}[!] Weak ciphers ({lw}|{total}):{fc.end}')
			for cs in groups['weak']:
				print(f'\t{cs}')

		if (ls):
			print(f'{fc.cyan}[+] Secure ciphers ({ls}|{total}):{fc.end}')
			for cs in groups['secure']:
				print(f'\t{cs}')

		if (lr):
			print(f'{fc.green}[✔] Recommended ciphers ({lr}|{total}):{fc.end}')
			for cs in groups['recommended']:
				print(f'\t{cs}')

	if outfile:
		print('_'*0x40)

		try:
			if len(all_weak_ciphers):
				with open(outfile, 'w+') as f:
					for cs in all_weak_ciphers:
						f.write(f'{cs}\n')
				print(f'{fc.blue}[i]{fc.end} Weak ciphers written to: {outfile}')
			else:
				print(f'{fc.blue}[i]{fc.end} No weak ciphers found')
		except Exception as e:
			print(f'{fc.red}[!]{fc.end} Failed to write results to {outfile}')
			return ERR
	return SUCC


if __name__ == '__main__':

	p = argparse.ArgumentParser(
		description=f"Parse sslyze output and pretty print supported cipher suites. Standing on the shoulders of {fc.cyan}https://ciphersuite.info/{fc.end}."
	)
	p.add_argument('inputfile', help=f'sslyze output in json format (use {fc.orange}sslyze --json_out <outfile> --targets_in <targets file>{fc.end})')
	p.add_argument('-s', '--openssl', action='store_true', default=False, help='use OpenSSL names instead of IANA')
	p.add_argument('-e', '--export', action='store', default=None, metavar='outfile', help="export all insecure and weak ciphers in one list")

	args = p.parse_args()

	if not os.path.isfile(args.inputfile):
		print(f'{fc.red}[!]{fc.end} Error: {args.inputfile} does not exist.')
		exit(ERR)

	if args.export and os.path.isfile(args.export):
		print(f'{fc.red}[!]{fc.end} Error: {args.export} already exist.')
		exit(ERR)

	if not checkInternet():
		print(f'{fc.red}[!]{fc.end} Failed connection test. Are you connected to the internet? This is required to query the ciphersuite.info API.')
		exit(ERR)
	status = main(args.inputfile, args.openssl, args.export)
	exit(status)
