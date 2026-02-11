import smtplib
import io


senderacc="quantanex.noreply@gmail.com"
senderpass="lxovmutrmgqsgwbf"
server='smtp.gmail.com'
port=587

def sendmail(id, message):
	s = smtplib.SMTP(server,port)
	s.starttls()
	s.login(senderacc, senderpass)
	s.sendmail(senderacc, id, message)
	s.quit()
	
	#MODIFY THIS FUNCTION TO USE YOUR INTERNAL MESSAGING
	#YOU MAY USE AD, SLACK OR ANY OTHER INTERNAL API YOU HAVE