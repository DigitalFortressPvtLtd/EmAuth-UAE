import json
import time
import pyodbc
import collections
import traceback
import random
from blobops import *
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
import time
import uuid

server = 'localhost'
database = 'mauthndb'
username = 'db_user'
password = '{Password12345*}'   
driver= '{ODBC Driver 17 for SQL Server}'
conn=pyodbc.connect('DRIVER='+driver+';SERVER=tcp:'+server+';PORT=1433;DATABASE='+database+';UID='+username+';PWD='+ password)
cursor=conn.cursor()

def createUsersTable():
	try:
		cursor.execute("CREATE TABLE [Users](id VARCHAR(50),email VARCHAR(50) UNIQUE,name VARCHAR(50), dob VARCHAR(15),imgblob VARCHAR(50),platformfidoblob VARCHAR(50),roamingfidoblob VARCHAR(50),authnperms VARCHAR(5), iottoken VARCHAR(6))")
		cursor.commit()
	except:
		pass

def createFinauthTable():
	try:
		cursor.execute("CREATE TABLE [Finauth](id VARCHAR(50),email VARCHAR(50))")
		cursor.commit()
	except:
		pass



def createAdminTable():
	try:
		cursor.execute("CREATE TABLE [Admin](id VARCHAR(50),email VARCHAR(50) UNIQUE)")
		cursor.commit()
	except:
		pass

def createTotpTable():
	try:
		cursor.execute("CREATE TABLE [Totp](id VARCHAR(50), service_name VARCHAR(50), account_label VARCHAR(50), secret_key VARCHAR(50), issuer VARCHAR(50), period VARCHAR(50), digits VARCHAR(50), algorithm VARCHAR(50), added_on VARCHAR(50))")
		cursor.commit()
	except:
		pass
		
def createSigninTable():
	try:
		cursor.execute("CREATE TABLE [Signin](token VARCHAR(50), id VARCHAR(50))")
		cursor.commit()
	except:
		pass
		
def createRequestsTable():
	try:
		cursor.execute("CREATE TABLE [Requests] (token VARCHAR(50),id VARCHAR(50),requester VARCHAR(500),ts VARCHAR(50),reqdata VARCHAR(50),grantedperms VARCHAR(5),location VARCHAR(50), ip VARCHAR(20))")
		cursor.commit()
	except:
		pass
		
def createLogsTable():
	try:
		cursor.execute("CREATE TABLE [Logs](token VARCHAR(50),id VARCHAR(50),requester VARCHAR(500),dtm VARCHAR(50),location VARCHAR(500))")
		cursor.commit()
	except:
		pass

def createSignupTable():
	try:
		cursor.execute("CREATE TABLE [Signup](token VARCHAR(50), id VARCHAR(50))")
		cursor.commit()
	except:
		pass

def createPreSignTable():
	try:
		cursor.execute("CREATE TABLE [PreSign](uploader VARCHAR(50), hash VARCHAR(70), title VARCHAR(256), signer VARCHAR(50))")
		cursor.commit()
	except:
		pass
		
def createPostSignTable():
	try:
		cursor.execute("CREATE TABLE [PostSign](uploader VARCHAR(50), hash_original VARCHAR(70), hash_signed VARCHAR(70), title VARCHAR(256), signer VARCHAR(50))")
		cursor.commit()
	except:
		pass

def createOIDCCodeTable():
	try:
		cursor.execute("CREATE TABLE [OIDCCode](userid VARCHAR(50), authcode VARCHAR(50), state VARCHAR(50), expire VARCHAR(50))")
		cursor.commit()
	except:
		pass

def createOIDCTokenTable():
	try:
		cursor.execute("CREATE TABLE[OIDCToken](userid VARCHAR(50), authtoken VARCHAR(50), refreshtoken VARCHAR(50), state VARCHAR(50), expire VARCHAR(50))")
		cursor.commit()
	except:
		pass

def createTables():
	createUsersTable()
	createSigninTable()
	createRequestsTable()
	createLogsTable()
	createSignupTable()
	createTotpTable()
	createAdminTable()
	createFinauthTable()
	createPreSignTable()
	createPostSignTable()
	createOIDCCodeTable()
	createOIDCTokenTable()

def resetTables():
	cursor.execute("DROP TABLE [Users]")
	cursor.execute("DROP TABLE [Signin]")
	cursor.execute("DROP TABLE [Requests]")
	cursor.execute("DROP TABLE [Logs]")
	cursor.execute("DROP TABLE [Signup]")
	cursor.execute("DROP TABLE [Totp]")
	cursor.execute("DROP TABLE [Admin]")
	cursor.execute("DROP TABLE [Finauth]")
	cursor.execute("DROP TABLE [PreSign]")
	cursor.execute("DROP TABLE [PostSign]")
	cursor.execute("DROP TABLE [OIDCCode]")
	cursor.execute("DROP TABLE [OIDCToken]")
	cursor.commit()
	createTables()

oidc_exp=600

def addOIDCCode(user, state):
	authcode=str(uuid.uuid4()).replace('-','')
	currtime=int(time.time())
	expire=str(currtime+oidc_exp)
	cursor.execute("INSERT INTO [OIDCCode] VALUES (?,?,?,?)", user, authcode, state, expire)
	cursor.commit()
	return authcode

def getUserFromOIDCCode(code):
	try:
		cursor.execute("SELECT userid, state, expire FROM [OIDCCode] WHERE authcode=?", code)
		resp=cursor.fetchone()
		user=resp[0]
		state=resp[1]
		expire=resp[2]
		cursor.execute("DELETE FROM [OIDCCode] WHERE authcode=?", code)
		cursor.commit()
		expire=int(expire)
		currtime=int(time.time())
		if currtime>expire:
			return '0000', '0000'
		return user, state
	except:
		return '0000', '0000'

def addOIDCTokenCode(code):
	authtoken=str(uuid.uuid4()).replace('-','')
	refreshtoken=str(uuid.uuid4()).replace('-','')
	currtime=int(time.time())
	expire=str(currtime+oidc_exp)
	user, state=getUserFromOIDCCode(code)
	if user=='0000':
		return '0000', '0000'
	cursor.execute("INSERT INTO [OIDCToken] VALUES (?,?,?,?,?)", user, authtoken, refreshtoken, state,expire)
	cursor.commit()
	return authtoken, refreshtoken

def addOIDCTokenRefresh(refresh):
	try:
		cursor.execute("SELECT expire FROM [OIDCToken] WHERE refreshtoken=?", refresh)
		resp=cursor.fetchone()
		expire=int(resp[0])
		currtime=int(time.time())
		if currtime>expire:
			cursor.execute("DELTE FROM [OIDCToken] WHERE refreshtoken=?", refresh)
			cursor.commit()
			return '0000'
		expire=str(currtime+oidc_exp)
		authtoken=str(uuid.uuid4()).replace('-','')
		cursor.execute("UPDATE [OIDCToken] SET authtoken=?, expire=? WHERE refreshtoken=?", authtoken, expire, refresh)
		cursor.commit()
		return authtoken
	except:
		return '0000'
	
def getUserDetailsOIDC(authtoken):
	try:
		cursor.execute("SELECT userid, expire, state FROM [OIDCToken] WHERE authtoken=?", authtoken)
		resp=cursor.fetchone()
		user=resp[0]
		expire=int(resp[1])
		state=resp[2]
		currtime=int(time.time())
		if currtime>expire:
			cursor.execute("DELETE FROM [OIDCToken] WHERE authtoken=?", authtoken)
			return '0000'
		cursor.execute("SELECT email, name, dob FROM [Users] WHERE id=?", user)
		data=cursor.fetchone()
		cursor.commit()
		dat={}
		dat['email']=data[0]
		dat['name']=data[1]
		dat['date-of-birth']=data[2]
		dat['state']=state
		return json.dumps(dat)
	except:
		return '0000'
	
def getUserImageOIDC(authtoken):
	try:
		cursor.execute("SELECT userid, expire, state FROM [OIDCToken] WHERE authtoken=?", authtoken)
		resp=cursor.fetchone()
		user=resp[0]
		expire=int(resp[1])
		state=resp[2]
		currtime=int(time.time())
		if currtime>expire:
			cursor.execute("DELETE FROM [OIDCToken] WHERE authtoken=?", authtoken)
			return '0000'
		cursor.execute("SELECT email, name, dob, imgblob FROM [Users] WHERE id=?", user)
		data=cursor.fetchone()
		cursor.commit()
		dat={}
		dat['email']=data[0]
		dat['name']=data[1]
		dat['date-of-birth']=data[2]
		dat['image']=downloadFile(data[3]).decode()
		dat['state']=state
		return json.dumps(dat)
	except:
		return '0000'
	
def revokeTokenOIDC(authtoken):
	try:
		cursor.execute("DELETE FROM [OIDCToken] WHERE authtoken=?", authtoken)
		cursor.commit()
	except:
		pass
	

def addPreSign(uploader, hash, title, signer):
	try:
		cursor.execute("INSERT INTO [PreSign] VALUES (?,?,?,?)", uploader, hash, title, signer)
		cursor.commit()
	except:
		pass

def getPreSignTitle(hash):
	try:
		cursor.execute("SELECT title FROM [PreSign] WHERE hash=?", hash)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		return "0000"
	
def getPreSignUploader(hash, signer):
	try:
		cursor.execute("SELECT uploader FROM [PreSign] WHERE hash=? AND signer=?", hash, signer)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		return "0000"
		
def getTitle(hash, uploader, signer):
	try:
		cursor.execute("SELECT title FROM [PreSign] WHERE hash=? AND uploader=? AND signer=?", hash, uploader, signer)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		return "0000"
	
def getAllSignsRequested(email):
	try:
		cursor.execute("SELECT title, hash, signer FROM [PreSign] WHERE uploader=?", email)
		ret=cursor.fetchall()
		cursor.commit()
		objects_list=[]
		for x in ret:
			d=collections.OrderedDict()
			d['title']=x[0]
			d['hash']=x[1]
			d['signer']=x[2]
			objects_list.append(d)
		return objects_list
	except:
		return "0000"
	
def getAllSignRequests(email):
	try:
		cursor.execute("SELECT title, hash, uploader FROM [PreSign] WHERE signer=?", email)
		ret=cursor.fetchall()
		cursor.commit()
		objects_list=[]
		for x in ret:
			d=collections.OrderedDict()
			d['title']=x[0]
			d['hash']=x[1]
			d['uploader']=x[2]
			objects_list.append(d)
		return objects_list
	except:
		return "0000"

def getSignerPost(hash_signed):
	try:
		cursor.execute("SELECT signer FROM [PostSign] WHERE hash_signed=?", hash_signed)
		signer=cursor.fetchone()[0]
		cursor.execute("SELECT name FROM [Users] WHERE email=?", signer)
		name = cursor.fetchone()[0]
		cursor.commit()
		return f'Digital Signture valid: Signed by {name}<{signer}>'
	except:
		return 'Signature could not be verified. File may be tampered.'


def checkPreSign(email, hash):
	try:
		cursor.execute("SELECT COUNT(*) FROM [PreSign] WHERE hash=? AND signer=?", hash, email)
		val=cursor.fetchone()[0]
		return val>0
	except:
		return False
	
def checkPreSignUploader(email, hash):
	try:
		cursor.execute("SELECT COUNT(*) FROM [PreSign] WHERE hash=? AND uploader=?", hash, email)
		val=cursor.fetchone()[0]
		return val>0
	except:
		return False
	
def removePreSign(uploader, hash, signer):
	try:
		cursor.execute("DELETE FROM [PreSign] WHERE uploader=? AND hash=? AND signer=?", uploader, hash, signer)
		cursor.commit()
	except:
		pass
	
def addPostSign(uploader, hash_original, hash_signed, title, signer):
	try:
		cursor.execute("INSERT INTO [PostSign] VALUES (?,?,?,?,?)", uploader, hash_original, hash_signed, title, signer)
		cursor.commit()
	except:
		pass

def checkPostSign(email, hash):
	try:
		cursor.execute("SELECT COUNT(*) FROM [PostSign] WHERE hash_signed=? AND signer=?", hash, email)
		val=cursor.fetchone()[0]
		return val>0
	except:
		return False

def checkPostSignUploader(email, hash):
	try:
		cursor.execute("SELECT COUNT(*) FROM [PostSign] WHERE hash_signed=? AND uploader=?", hash, email)
		val=cursor.fetchone()[0]
		return val>0
	except:
		return False


def checkPostSignOrig(email, hash):
	try:
		cursor.execute("SELECT COUNT(*) FROM [PostSign] WHERE hash_original=? AND signer=?", hash, email)
		val=cursor.fetchone()[0]
		return val>0
	except:
		return False

def checkPostSignUploaderOrig(email, hash):
	try:
		cursor.execute("SELECT COUNT(*) FROM [PostSign] WHERE hash_original=? AND uploader=?", hash, email)
		val=cursor.fetchone()[0]
		return val>0
	except:
		return False
	
def gethashsigned(email, hash):
	try:
		cursor.execute("SELECT hash_signed FROM [PostSign] WHERE hash_original=? AND signer=?", hash, email)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		return "0000"

def getAllSignedMe(email):
	try:
		cursor.execute("SELECT title, hash_original, hash_signed, uploader FROM [PostSign] WHERE signer=?", email)
		ret=cursor.fetchall()
		cursor.commit()
		objects_list=[]
		for x in ret:
			d=collections.OrderedDict()
			d['title']=x[0]
			d['originalHash']=x[1]
			d['hash']=x[2]
			d['uploader']=x[3]
			objects_list.append(d)
		return objects_list
	except:
		return "0000"

def getAllSigned(email):
	try:
		cursor.execute("SELECT title, hash_original, hash_signed, signer FROM [PostSign] WHERE uploader=?", email)
		ret=cursor.fetchall()
		cursor.commit()
		objects_list=[]
		for x in ret:
			d=collections.OrderedDict()
			d['title']=x[0]
			d['originalHash']=x[1]
			d['hash']=x[2]
			d['signer']=x[3]
			objects_list.append(d)
		return objects_list
	except:
		return "0000"

def addAdmin(id, email):
	if checkAdmin(email):
		return
	try:
		cursor.execute("INSERT INTO [Admin] VALUES (?,?)", id, email)
		cursor.commit()
	except:
		pass

def addFinauth(id, email):
	try:
		cursor.execute("INSERT INTO [Finauth] VALUES (?,?)", id, email)
		cursor.commit()
	except:
		pass

def getFinauth(id):
	try:
		cursor.execute("SELECT email FROM [Finauth] WHERE id=?",id)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		print(traceback.format_exc())
		return "0000"
	

def getIdFromTokenSignin(token): #get from sign in table
	try:
		cursor.execute("SELECT id FROM [Signin] WHERE token=?",token)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		print(traceback.format_exc())
		return "0000"
		
def removeTokenFromSignin(token): #remove from signin table
	try:
		cursor.execute("DELETE FROM [Signin] WHERE token=?",token)
		cursor.commit()
	except:
		#print(traceback.format_exc())
		pass
		
def getIdFromToken(token): #get from Requests table
	try:
		cursor.execute("SELECT id FROM [Requests] WHERE token=?",token)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		return "0000"

def getImgBlobFromId(id): #Get from userstable
	try:
		cursor.execute("SELECT imgblob FROM [Users] WHERE id=?",id)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		#print(traceback.format_exc())
		return "0000"

def getGrantedPerms(token): #Get from requests table
	try:
		cursor.execute("SELECT grantedperms FROM [Requests] WHERE token=?",token)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		#print(traceback.format_exc())
		return "0000"
		#try:
		#	if(checkTokenExistRequests(token)):
		#		id=getIdFromToken(token)
		#		return getAuthnPerms(id)
		#except:
		#	print(traceback.format_exc())
		#	return "0000"

def getAuthnPerms(id): #Get from Users table
	try:
		cursor.execute("SELECT authnperms FROM [Users] WHERE id=?",id)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		return "0000"

def updateGrantedPerms(token, param, location="0,0"): #Update requests table
	gperm=getGrantedPerms(token)
	face=gperm[0]
	plat=gperm[1]
	roam=gperm[2]
	try:
		if param=='face' or face!='1':
			cursor.execute("UPDATE [Requests] SET location=? WHERE token=?",location,token)
	except:
		pass
	if param=='face':
		face='1'
	if param=='platform':
		plat='1'
	if param=='roaming':
		roam='1'
	gperm=face+plat+roam
	try:
		cursor.execute("UPDATE [Requests] SET grantedperms=? WHERE token=?",gperm,token)
		cursor.commit()
	except:
		#print(traceback.format_exc())
		pass
		
def getPlatformBlobFromId(id): #Get from Users table
	try:
		cursor.execute("SELECT platformfidoblob FROM [Users] WHERE id=?",id)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		#print(traceback.format_exc())
		return "0000"

def getRoamingBlobFromId(id): #Get from Users table
	try:
		cursor.execute("SELECT roamingfidoblob FROM [Users] WHERE id=?",id)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		#print(traceback.format_exc())
		return "0000"

def checkGrantedPerms(token,param): #From Requests table
	gperm=getGrantedPerms(token)
	face=gperm[0]
	plat=gperm[1]
	roam=gperm[2]
	if param=='face':
		return face=='1'
	if param=='platform':
		return plat=='1'
	if param=='roaming':
		return roam=='1'
	return False

def checkAdmin(email):
	try:
		cursor.execute("SELECT COUNT(*) FROM [Admin] WHERE email=?", email)
		val=cursor.fetchone()[0]
		print(val)
		return val>0
	except:
		return False
		

def addToRequest(token,id,requester,ts,reqdata,ip): #Insert to requests table ts to str
	try:
		cursor.execute("INSERT INTO [Requests] VALUES (?,?,?,?,?,?,?,?)",token,id,requester,str(ts),reqdata,"000","0,0",ip)
		cursor.commit()
	except:
		#print(traceback.format_exc())
		pass

def addToTotp(id, service_name, account_label, secret_key, issuer, period, digits, algorithm, added_on): #Insert to requests table ts to str
	try:
		cursor.execute("INSERT INTO [Totp] VALUES (?,?,?,?,?,?,?,?,?)",id, service_name, account_label, secret_key, issuer, period, digits, algorithm, added_on)
		cursor.commit()
	except:
		#print(traceback.format_exc())
		pass

def getRequesterFromToken(token): #Get from Requests table
	try:
		cursor.execute("SELECT requester FROM [Requests] WHERE token=?",token)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		return "0000"
	
def getLocationFromToken(token): #Get from Requests table
	try:
		cursor.execute("SELECT location FROM [Requests] WHERE token=?",token)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		return "0000"

def getIPFromToken(token): #Get from Requests table
	try:
		cursor.execute("SELECT ip FROM [Requests] WHERE token=?",token)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		return "0000"

def addToLogs(token,id,requester,dtm,loc): #Add to logs table
	try:
		cursor.execute("INSERT INTO [Logs] VALUES (?,?,?,?,?)",token,id,requester,dtm,loc)
		cursor.commit()
	except:
		print(traceback.format_exc())
		pass
		
def remove_request(token): #Delete from Requests table
	try:
		cursor.execute("DELETE FROM [Requests] WHERE token=?",token)
		cursor.commit()
	except:
		pass

def addToUsers(id,email,name,dob,imgblob,platformfidoblob,roamingfidoblob,authnperms): #Add to users table
	try:
		iottoken=getRandomToken()
		cursor.execute("INSERT INTO [Users] VALUES (?,?,?,?,?,?,?,?,?)",id,email,name,dob,imgblob,platformfidoblob,roamingfidoblob,authnperms,iottoken)
		cursor.commit()
	except:
		#print(traceback.format_exc())
		pass
	
def getNameFromEmail(email): #Get from Users table
	try:
		cursor.execute("SELECT name FROM [Users] WHERE email=?",email)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		#print(traceback.format_exc())
		return "0000"

def getRandomToken():
	digits=6
	lower = 10**(digits-1)
	upper = 10**digits - 1
	xx=str(random.randint(lower, upper))
	return xx.replace('0', str(random.randint(1, 9)))

def getIotFromId(id):
	try:
		cursor.execute("SELECT iottoken FROM [Users] WHERE id=?", id)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		return "0000"
	
def getIdFromIot(iot):
	try:
		cursor.execute("SELECT id FROM [Users] WHERE iottoken=?", iot)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		return "0000"


def addToSignUp(id,token): #Add to sign up table
	try:
		cursor.execute("INSERT INTO [Signup] VALUES (?,?)",token,id)
		cursor.commit()
	except:
		#print(traceback.format_exc())
		pass
		
def addToSignIn(token,id): #Add to sign in table
	try:
		cursor.execute("INSERT INTO [Signin] VALUES (?,?)",token,id)
		cursor.commit()
	except:
		#print(traceback.format_exc())
		pass
		
def getIdFromSignUpToken(token): #Get from sign up table
	try:
		cursor.execute("SELECT id FROM [Signup] WHERE token=?",token)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		#print(traceback.format_exc())
		return "0000"

def getEmailFromId(id): #Get from users table
	try:
		cursor.execute("SELECT email FROM [Users] WHERE id=?",id)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		#print(traceback.format_exc())
		return "0000"

def getIdFromEmail(email): #get from Users table
	try:
		cursor.execute("SELECT id FROM [Users] WHERE email=?",email)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		#print(traceback.format_exc())
		return "0000"

def enableAuthnPerms(id, param): #Update users table
	gperm=getAuthnPerms(id)
	face=gperm[0]
	plat=gperm[1]
	roam=gperm[2]
	if param=='face':
		face='1'
	if param=='platform':
		plat='1'
	if param=='roaming':
		roam='1'
	gperm=face+plat+roam
	try:
		cursor.execute("UPDATE [Users] SET authnperms=? WHERE id=?",gperm,id)
		cursor.commit()
	except:
		#print(traceback.format_exc())
		pass

def removeFromSignUp(token): #Remove from sign up table
	try:
		cursor.execute("DELETE FROM [Signup] WHERE token=?",token)
		cursor.commit()
	except:
		#print(traceback.format_exc())
		pass

def getTimeStampFromToken(token): #Get from requests table return INT
	try:
		cursor.execute("SELECT ts FROM [Requests] WHERE token=?",token)
		ret=cursor.fetchone()[0]
		cursor.commit()
		return int(ret)
	except:
		#print(traceback.format_exc())
		return 0
	
def checkTokenExistLog(token): #Get from logs
	try:
		cursor.execute("SELECT COUNT(*) FROM [Logs] WHERE token=?",token)
		x=int(cursor.fetchone()[0])
		cursor.commit()
		return x>0
	except:
		return False

def checkTokenExistRequests(token): #Get from Requests
	try:
		cursor.execute("SELECT COUNT(*) FROM [Requests] WHERE token=?",token)
		x=int(cursor.fetchone()[0])
		cursor.commit()
		return x>0
	except:
		return False

def removeExpiredRequests(id,expthreshhold): #Remove from Requests table
	cts=int(time.time())
	removeExpiredOIDCCodes()
	try:
		cursor.execute("SELECT token, ts FROM [Requests] WHERE id=?",id)
		lst=cursor.fetchall()
		cursor.commit()
		for rec in lst:
			token=rec[0]
			ts=int(rec[1])
			if cts-ts>int(expthreshhold):
				remove_request(token)
	except:
		#print(traceback.format_exc())
		pass

def removeExpiredOIDCCodes():
	currtime=int(time.time())
	cursor.execute("SELECT authcode, expire FROM [OIDCCode]")
	tokens=cursor.fetchall()
	for x in tokens:
		auth=x[0]
		expire=int(x[1])
		if currtime>expire:
			cursor.execute("DELETE FROM [OIDCCode] WHERE authcode=?", auth)
			cursor.commit()
	cursor.execute("SELECT authtoken, expire FROM [OIDCToken]")
	tokens=cursor.fetchall()
	for x in tokens:
		auth=x[0]
		expire=int(x[1])
		if currtime>expire:
			cursor.execute("DELETE FROM [OIDCToken] WHERE authtoken=?", auth)
			cursor.commit()

	
	

def getTotpFromID(id): #get from requests table JSON, perms from User
	try:
		cursor.execute("SELECT service_name, account_label, secret_key, issuer, period, digits, algorithm, added_on FROM [Totp] WHERE id=?",id)
		data=cursor.fetchall()
		cursor.commit()
		objects_list=[]
		for x in data:
			d=collections.OrderedDict()
			d['service_name']=x[0]
			d['account_label']=x[1]
			d['secret_key']=x[2]
			d['issuer']=x[3]
			d['period']=x[4]
			d['digits']=x[5]
			d['algorithm']=x[6]
			d['added_on']=x[7]
			objects_list.append(d)
		objects_list.reverse()
		j=json.dumps(objects_list)
		return j
	except:
		#print(traceback.format_exc())
		return "0000"

def delTotp(id, secret_key):
	try:
		cursor.execute("DELETE FROM [Totp] WHERE id=? AND secret_key=?", id, secret_key)
		cursor.commit()
		return 'True'
	except:
		return 'False'

def getRequestsFromID(id): #get from requests table JSON, perms from User
	try:
		aperm=getAuthnPerms(id)
		cursor.execute("SELECT token, requester, reqdata, ts FROM [Requests] WHERE id=?",id)
		data=cursor.fetchall()
		cursor.commit()
		objects_list=[]
		for x in data:
			d=collections.OrderedDict()
			d['token']=x[0]
			d['requester']=x[1]
			d['reqdata']=x[2]
			d['perms']=aperm
			d['timestamp']=x[3]
			objects_list.append(d)
		objects_list.reverse()
		j=json.dumps(objects_list)
		return j
	except:
		#print(traceback.format_exc())
		return "0000"
		
def getReqData(token): #Get from requests table
	try:
		cursor.execute("SELECT reqdata FROM [Requests] where token=?",token)
		ret= cursor.fetchone()[0]
		cursor.commit()
		return ret
	except:
		#print(traceback.format_exc())
		return "0000"
		
def getLogsFromID(id): #get from logs table JSON
	try:
		cursor.execute("SELECT requester, dtm, token FROM [Logs] WHERE id=? ORDER BY dtm DESC",id)
		data=cursor.fetchall()
		cursor.commit()
		objects_list=[]
		for x in data:
			d=collections.OrderedDict()
			d['requester']=x[0]
			d['timestamp']=x[1]
			d['token']=x[2]
			objects_list.append(d)
		#objects_list.reverse()
		j=json.dumps(objects_list)
		return j
	except:
		#print(traceback.format_exc())
		return "0000"

def checkUserExist(email):
	try:
		cursor.execute("SELECT COUNT(*) FROM [Users] WHERE email=?", email)
		num=cursor.fetchone()[0]
		cursor.commit()
		return num>0
	except:
		return False

def logCount():
	try:
		cursor.execute("SELECT COUNT(*) FROM [Logs]")
		count=cursor.fetchall()[0][0]
		return str(count)
	except:
		return '0'

def getAllLogs(): #get from logs table JSON
	try:
		cursor.execute("SELECT name, email, requester, dtm, location FROM [Logs] INNER JOIN [Users] ON [Users].id=[Logs].id ORDER BY dtm DESC")
		data=cursor.fetchall()
		cursor.commit()
		objects_list=[]
		for x in data:
			d=collections.OrderedDict()
			d['name']=x[0]
			d['email']=x[1]
			d['requester']=x[2]
			d['timestamp']=x[3]
			d['ip']=x[4]
			objects_list.append(d)
		#objects_list.reverse()
		j=json.dumps(objects_list)
		return j
	except:
		#print(traceback.format_exc())
		return "0000"
	
def getAllUsers(): #get from Users table JSON
	try:
		cursor.execute("SELECT name, email FROM [Users]")
		data=cursor.fetchall()
		cursor.commit()
		objects_list=[]
		for x in data:
			d=collections.OrderedDict()
			d['name']=x[0]
			d['email']=x[1]
			objects_list.append(d)
		#objects_list.reverse()
		j=json.dumps(objects_list)
		return j
	except:
		#print(traceback.format_exc())
		return "0000"

def getResponse(reqdata,id,token, loc1): #get from Users table
	if reqdata=="0000":
		return json.dumps({"Verification":True})
	try:
		cursor.execute("SELECT name, dob, imgblob FROM [Users] WHERE id=?",id)
		data=cursor.fetchone()
		cursor.commit()
		name=data[0]
		dob=data[1]
		imgblob=data[2]
		
		cursor.execute("SELECT location FROM [Requests] WHERE token=?",token)
		loc=cursor.fetchone()[0]
		objects_list=[]
		d=collections.OrderedDict()
		if reqdata[0] == '1':
			d['name']=name
		if reqdata[1] == '1':
			d['date-of-birth']=dob
		if reqdata[2] == '1':
			image=downloadFile(imgblob)
			d['image']=str(image.decode())
		if reqdata[3]=='1':
			d['location']=loc
		d['claimant']=loc1
		objects_list.append(d)
		j=json.dumps(objects_list)
		return j
	except:
		#print(traceback.format_exc())
		return "0000"
		
def get_recent_user_emails(months=1):
	try:
		current_date = datetime.now()
		one_month_ago = current_date - relativedelta(months=months)
		one_month_ago_str = one_month_ago.strftime('%Y/%m/%d %H:%M:%S')
		query = "SELECT DISTINCT u.email FROM [Users] u INNER JOIN [Logs] l ON u.id = l.id WHERE CONVERT(datetime, l.dtm, 120) >= ?"
		cursor.execute(query, (one_month_ago_str,))
		results = cursor.fetchall()
		emails = [row[0] for row in results]
		return emails
	except:
		return []
    
