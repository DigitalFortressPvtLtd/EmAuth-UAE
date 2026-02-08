import requests
import time
from masterurl import *
def send_request(email_of_user, required_data, requester):
	url=f'https://{deployed_domain}/add_request'
	params={'email': email_of_user, 'data':required_data, 'requester':requester}
	r=requests.post(url, data=params)
	token=r.text
	
	if token.startswith("0000"):
		raise Exception("Account does not exist")
	
	status="pending"
	while(status.startswith('pending')):
		time.sleep(10)
		url=f'https://{deployed_domain}/get_data'
		params={'token': token[:36]}
		r=requests.post(url, data=params)
		status=r.text
		
	if status.startswith('expired'):
		return "Authorization denied"
	else:
		return status
		
def verifyUser(email_of_user, requester='', parent=''):
	print('Starting authentication')
	k=send_request(email_of_user,"0000",requester)
	y= not k=='Authorization denied'
	print('Authentication ',y)
	return y

def getUserData(email_of_user, requested_data, requester='', parent=''):
	data=''
	if 'Name' in requested_data:
		data=data+'1'
	else:
		data=data+'0'
	if 'Date-Of-Birth' in requested_data:
		data=data+'1'
	else:
		data=data+'0'
	if 'Image' in requested_data:
		data=data+'1'
	else:
		data=data+'0'
	if 'IP' in requested_data:
		data=data+'1'
	else:
		data=data+'0'
		
	resp=send_request(email_of_user,data,requester)
	return resp
