from emailops import *
from dbops import *

def featureDrop(name, txt, recentmonths=1):
	emaillist=get_recent_user_emails(months=recentmonths)
	featureDropMail(emaillist, name, txt)
	print('Email Sent to')
	for email in emaillist:
		print(email)
		
if __name__=='__main__':
	name=input("Enter new feature name: ")
	txt=input("Enter feature description: ")
	featureDrop(name, txt)
