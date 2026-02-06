from masterurl import *
from emailsender import *
def sendEmail(id,token):
	message = "Subject:Authorization Token\n\nThe Token for Authorization is "+token
	sendmail(id, message)
	
def sendSignupEmail(email,token):
	message = f'Subject:Account creation link\n\nThe link to set up MAuthN account is https://{deployed_domain}/email_signup_user?token='+token
	sendmail(email, message)

def sendNewReqMail(email, requester):
	message = "Subject:Authentication Request\n\nNew authentication request on MAuthN. Details:\n"+requester+"\n\nCheck the app for more details."
	sendmail(email, message)

def sendSuccessReqMail(email, requester):
	message = "Subject:Authentication Success\n\nAuthentication sucessful. Details:\n"+requester+"\n\nContact admin if not done by you."
	sendmail(senderacc, email, message)

def adminPromoteMail(email):
	message = f"Subject:Promote to Admin\n\nYou have been promoted to admin in MAuthN. To go to admin dashboard, use https://{deployed_domain}/admin"
	sendmail(email, message)

def signInitMail(email, title):
	message = f'Subject:New Document signing request\n\nYou have a request to sign a document for {title}. Check the app for more details.'
	sendmail(email, message)

def signReminderMail(email, title):
	message = f'Subject:Reminder Document signing \n\nYou have a pending request to sign a document for {title}. Check the app for more details.'
	sendmail(email, message)

def signCompleteMail(email, title, signer):
	message = f'Subject:Document signing complete\n\nDocument signing for {title} is completed by {signer}. Check the app for more details.'
	sendmail(email, message)

def appUpdate(emaillist):
	message = "Subject:App Update Available\n\nA new update for MAuthN app is available. Download it for your phone from your administrator."
	for email in emaillist:
		sendmail(email, message)

def featureDropMail(emaillist, name, txt):
	message = f'Subject:Feature Drop {name}\n\nNew feature {name} available. {txt}'
	for email in emaillist:
		sendmail(email, message)
