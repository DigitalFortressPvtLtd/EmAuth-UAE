from masterurl import *
from emailsender import *
def sendEmail(id,token, prod):
	message = "Subject:Authorization Token\n\nThe Token for Authorization is "+token
	sendmail(id, message)
	
def sendSignupEmail(email,token, prod):
	message = f'Subject:Account creation link\n\nThe link to set up Quantanex.io account is https://{deployed_domain}/email_signup_user?token='+token
	sendmail(email, message)

def sendNewReqMail(email, requester, prod):
	message = "Subject:Authentication Request\n\nNew authentication request on Quantanex.io. Details:\n"+requester+"\n\nCheck the app for more details."
	sendmail(email, message)

def sendSuccessReqMail(email, requester, prod):
	message = "Subject:Authentication Success\n\nAuthentication sucessful. Details:\n"+requester+"\n\nContact admin if not done by you."
	sendmail(senderacc, email, message)

def adminPromoteMail(email, prod):
	message = f"Subject:Promote to Admin\n\nYou have been promoted to admin in Quantanex.io. To go to admin dashboard, use https://{deployed_domain}/admin"
	sendmail(email, message)

def signInitMail(email, title, prod):
	message = f'Subject:New Document signing request\n\nYou have a request to sign a document for {title}. Check the app for more details.'
	sendmail(email, message)

def signReminderMail(email, title, prod):
	message = f'Subject:Reminder Document signing \n\nYou have a pending request to sign a document for {title}. Check the app for more details.'
	sendmail(email, message)

def signCompleteMail(email, title, signer, prod):
	message = f'Subject:Document signing complete\n\nDocument signing for {title} is completed by {signer}. Check the app for more details.'
	sendmail(email, message)

def appUpdate(emaillist, prod):
	message = "Subject:App Update Available\n\nA new update for app is available. Download it for your phone from your administrator."
	for email in emaillist:
		sendmail(email, message)

def featureDropMail(emaillist, name, txt, prod):
	message = f'Subject:Feature Drop {name}\n\nNew feature {name} available. {txt}'
	for email in emaillist:
		sendmail(email, message)
