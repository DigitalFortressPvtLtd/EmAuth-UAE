import requests, json
import re

def getStatus(ip_address):
  ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
  match = re.search(ipv4_pattern, ip_address)
  ip_address=match.group()
  return ''

# VPN API unavailable in offline deployment mode