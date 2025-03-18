from dbops import *

def createLogoutTable():
	try:
		cursor.execute("CREATE TABLE [Logout](id VARCHAR(50), token VARCHAR(50))")
		cursor.commit()
	except:
		pass
		
def addLogout(id, token):
	try:
		cursor.execute("SELECT * FROM [Logs] WHERE token=? AND id=?", token, id)
		res=cursor.fetchall()
		cursor.commit()
		if len(res)==0:
			return False
		cursor.execute("SELECT * FROM [Logout] WHERE token=? AND id=?", token, id)
		res1=cursor.fetchall()
		if len(res1)>0:
			return False
		cursor.execute("INSERT INTO [Logout] VALUES(?,?)", id, token)
		cursor.commit()
		return True
	except:
		return False
		
def checkLogout(token):
	try:
		cursor.execute("SELECT * FROM [Logout] WHERE token=?",  token)
		res1=cursor.fetchall()
		if len(res1)>0:
			return True
		return False
	except:
		return True
		
def getInSessions(signoutall=False): #Only for testing
	try:
		cursor.execute("SELECT id, token FROM [Logs]")
		r1=cursor.fetchall()
		cursor.commit()
		for x in r1:
			id=x[0]
			token=x[1]
			if not checkLogout(token):
				print(id, token)
				if signoutall:
					addLogout(id, token)
	except:
		pass
