deployed_domain='mauthn.mukham.in'

import requests
def check_domain_valid():
	resp=requests.get(f'https://{deployed_domain}/checkdomain', verify=False)
	data=resp.text
	tempf=open('/etc/mauthn/temp','r')
	data2=tempf.read()
	return data==data2
