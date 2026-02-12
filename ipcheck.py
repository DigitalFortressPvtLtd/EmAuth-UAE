import requests, json
import re

def getStatus(ip_address, product='QuantaNex'):
  global currentip
  ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
  match = re.search(ipv4_pattern, ip_address)
  ip_address=match.group()
  
  apikey1='6e64bf29dd58442aa91ec'
  apikey2='75d2ed665d6'
  API_key=apikey1+apikey2
  response = requests.get("https://vpnapi.io/api/" + ip_address + "?key=" + API_key)
  data = json.loads(response.text)
  if ip_address==currentip:
    op=f' ({product} Genuine Request)'
    op=op+" - Country Code: "+str(data["location"]["country_code"])
    return op
  op=''
  if data["security"]["vpn"]:
    op=op+' (VPN Used)'
  if data["security"]["proxy"]:
    op=op+' (Proxy Used)'
  if data["security"]["tor"]:
    op=op+' (Tor Used)'
  op=op+" - "+str(data["network"]["autonomous_system_organization"])+" - Country Code: "+str(data["location"]["country_code"])
  return op

def getCurrentIp():
  global currentip
  response=requests.get('https://api.ipify.org?format=json')
  data=json.loads(response.text)
  currentip=data['ip']
  return currentip

getCurrentIp()
