from __future__ import print_function, absolute_import, unicode_literals

from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.client import ClientData
from fido2.server import Fido2Server
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2 import cbor
from flask import *
from cryptography.fernet import Fernet
from datetime import datetime
from os import path
from dbops import *
from blobops import *
from emailops import *
from faceoperations import *
from pyMAuthN import *
from ipcheck import *
from getintent import *
from user_agents import parse
from io import BytesIO
import traceback
import base64
import requests
import pickle
import string
import random
import os
import uuid
import time
import pytz
import hashlib
from logout import *
from flask_cors import CORS
from PyPDF2 import PdfReader, PdfWriter
from PIL import *
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
import gc
import bleach
from masterurl import *
from offlineverif import *

tz = pytz.timezone('Asia/Calcutta')


timeout=600 #10 mins
recentmonths=1
url=deployed_domain
filepth='/etc/mauthn/'
app = Flask(__name__, static_url_path="")
CORS(app)

createTables()
createContainers()

if not path.exists(filepth+'appfiles/'+'appseckey.pkl'):
	outp3=open(filepth+'appfiles/'+'appseckey.pkl','wb')
	pickle.dump(os.urandom(32),outp3,pickle.HIGHEST_PROTOCOL)
	outp3.close()

inp3=open(filepth+'appfiles/'+'appseckey.pkl', 'rb')
app.secret_key = pickle.load(inp3)
inp3.close()

rp = PublicKeyCredentialRpEntity(url, "MAuthn")
server = Fido2Server(rp)

if not path.exists(filepth+'appfiles/'+'fernetkey.pkl'):
	with open(filepth+'appfiles/'+'fernetkey.pkl','wb') as outp1:
		pickle.dump(Fernet.generate_key(),outp1,pickle.HIGHEST_PROTOCOL)
		
inp=open(filepth+'appfiles/'+'fernetkey.pkl', 'rb')
key=pickle.load(inp)
inp.close()
fkey=Fernet(key)

def get_productname(request):
	#if (request.host is not None and 'emauth' in request.host.lower()) or (request.referrer is not None and 'emauth' in request.referrer.lower()) or 'emauth' in request.args.get('parent', '').lower():
	#	return 'EmAuth'
	#return 'MAuthN'	
	return 'EmAuth'

def getproductname_link(request):
	name=get_productname(request)
	link=name.lower()
	print(f'Using name {name} for email')
	return name,link

@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html', productname=get_productname(request)), 404

@app.route("/getproductname")
def getproductname():
	return get_productname(request)

@app.route("/dfp.png")
def dfplogo():
	if get_productname(request).lower()=='emauth':
		return redirect('/il_logo.png')	
	else:
		return redirect('/dfp_logo.png')

@app.route("/.well-known/webauthn")
def wellknown():
	return jsonify({'origins':['https://mauthn.mukham.in', 'https://emauth.mukham.in']})

@app.route("/analyticsdashboard", methods=['GET', 'POST'])
def analyticsdashboard():
	return redirect('https://analytics.mauthn.mukham.in/')

@app.route("/", methods=["GET", "POST"])
def homeindex():
	return render_template("homepage.html", productname=get_productname(request))

@app.route("/all_logs", methods=["GET","POST"])
def all_logs():
	if request.cookies.get('authorization') == 'authorized' or ('logsauth' in request.headers and request.headers.get('logsauth')=='authorized'):
		resp=make_response(getAllLogs())
		resp.headers.add('Access-Control-Allow-Origin', '*')
		return resp
	return "Session expired. Please logout and login."

@app.route("/all_users", methods=["GET","POST"])
def all_users():
	if request.cookies.get('authorization') != 'authorized':
		return "Session expired. Please logout and login."
	return getAllUsers()

@app.route("/admin", methods=["GET", "POST"])
def adminpage():
	if request.cookies.get('authorization') != 'authorized':
		return render_template("adminlogin.html", productname=get_productname(request))
	return redirect('/dashboard')

@app.route("/payeraccount", methods=["GET", "POST"])
def payeraccount():
	authcode=request.headers['authorizationcode']
	authemail=getFinauth(authcode)
	if authemail=='0000':
		resp=make_response('Unauthorized request')
		resp.headers.add('Access-Control-Allow-Origin', '*')
		return resp
	email=bleach.clean(request.form['email'])
	id='0000'
	if '@' in email:
		id=getIdFromEmail(email) #get from Users table
	else:
		id=getIdFromIot(email)
	if id=='0000':
		resp=make_response('0000')
		resp.headers.add('Access-Control-Allow-Origin', '*')
		return resp
	if getAuthnPerms(id)=='010':
		resp=make_response('True')
		resp.headers.add('Access-Control-Allow-Origin', '*')
		return resp
	else:
		resp=make_response('False')
		resp.headers.add('Access-Control-Allow-Origin', '*')
		return resp

@app.route("/dashboardlogin", methods=["GET", "POST"])
def dashboardlogin():
	email=bleach.clean(request.form['email'])
	if verify_signature(email):
		resp=make_response(redirect('/dashboard'))
		resp.set_cookie('authorization','authorized', max_age = 3600)
		resp.set_cookie('id','ServiceAccount@mauthn', max_age = 3600)
		return resp
	if not checkAdmin(email):
		return 'Unauthorized'
	if not verifyUser(email, f'{get_productname(request)} Admin login', parent=get_productname(request)):
		return 'Login failed'
	resp=make_response(redirect('/dashboard'))
	resp.set_cookie('authorization','authorized', max_age = 3600)
	resp.set_cookie('id',email, max_age = 3600)
	return resp

@app.route("/signerloginapp", methods=["GET", "POST"])
def signerloginapp():
	id=bleach.clean(request.args.get('id'))
	email=getEmailFromId(id)
	resp=make_response(redirect('/signdashboard'))
	resp.set_cookie('authorization','signerauthorized', max_age = 3600)
	resp.set_cookie('id',email, max_age = 3600)
	return resp

@app.route("/signersignin", methods=["GET", "POST"])
def signersignin():
	return render_template("signerlogin.html", productname=get_productname(request))

@app.route("/signerlogin", methods=["GET", "POST"])
def signerlogin():
	email=bleach.clean(request.form['email'])
	if not verifyUser(email, f'{get_productname(request)} Document Signing Login', parent=get_productname(request)):
		return 'Login failed'
	resp=make_response(redirect('/signdashboard'))
	resp.set_cookie('authorization','signerauthorized', max_age = 3600)
	resp.set_cookie('id',email, max_age = 3600)
	return resp

@app.route("/signdashboard", methods=["GET", "POST"])
def signdashboard():
	if request.cookies.get('authorization') != 'signerauthorized':
		return redirect('/dashboardlogout')
	return render_template("signer_dashboard.html", productname=get_productname(request))

@app.route("/uploadpage", methods=["GET", "POST"])
def uploadpage():
	return render_template("fileupload.html", productname=get_productname(request))

@app.route("/fileviewer", methods=["GET", "POST"])
def fileviewer():
	hash=bleach.clean(request.args.get('hash'))
	return render_template("fileviewer.html", filehash=hash, productname=get_productname(request))

@app.route("/adminsignvalidate", methods=["GET", "POST"])
def adminsignvalidate():
	if request.cookies.get('authorization') != 'authorized':
		return "Session expired. Please logout and login."
	email=request.cookies.get('id')
	hash=bleach.clean(request.args.get('hash'))
	signer=bleach.clean(request.args.get('signer'))
	if not checkAdmin(email):
		return "Unauthorized"
	signed_hash=gethashsigned(signer, hash)
	return redirect("/fileviewer?hash="+signed_hash)

@app.route("/signupload", methods=["GET", "POST"])
def signupload():
	if request.cookies.get('authorization') != 'signerauthorized':
		return "Session expired. Please logout and login."
	email=request.cookies.get('id')
	file=request.files['file']
	title=bleach.clean(request.form['title'])
	if not file.filename.endswith('.pdf'):
		return "Error: Only PDF files are allowed."
	filename=str(uuid.uuid4())+'.pdf'
	file_content = file.read()
	file_hash = hashlib.sha256(file_content).hexdigest()
	uploadFile(file_content, file_hash)
	toSign=bleach.clean(request.form['tosign'])
	if not checkUserExist(toSign):
		return "Error: User not found"
	addPreSign(email, file_hash, title, toSign)
	signInitMail(toSign, title,getproductname_link(request))
	return "File uploaded successfully"
	
@app.route("/signdownload", methods=["GET", "POST"])
def signdownload():
	if request.cookies.get('authorization') != 'signerauthorized' and request.cookies.get('authorization') != 'authorized':
		return "Session expired. Please logout and login."
	email=request.cookies.get('id')
	filehash=bleach.clean(request.form['filehash'])
	if checkPreSign(email, filehash) or checkPreSignUploader(email, filehash) or checkPostSign(email, filehash) or checkPostSignUploader(email, filehash) or checkPostSignOrig(email, filehash) or checkPostSignUploaderOrig(email, filehash) or checkAdmin(email):
		file_content=downloadFile(filehash)
		return send_file(BytesIO(file_content), as_attachment=True, attachment_filename=filehash+'.pdf')
	else:
		return "Unauthorized"
	
@app.route("/signremind", methods=["GET", "POST"])
def signremind():
	if request.cookies.get('authorization') != 'signerauthorized':
		return "Session expired. Please logout and login."
	email=request.cookies.get('id')
	hash=bleach.clean(request.form['hash'])
	signer=bleach.clean(request.form['signer'])
	title=getTitle(hash, email, signer)
	signReminderMail(signer, title,getproductname_link(request))
	return "Reminder sent"

@app.route("/sign", methods=["GET", "POST"])
def sign():
	from PIL import Image
	import PIL
	Image.VERSION=PIL.__version__
	cms_signer = signers.SimpleSigner.load(cert_file=filepth+'certificate.pem', key_file=filepth+'privatekey.pem')
	
	if request.cookies.get('authorization') != 'signerauthorized':
		return "Session expired. Please logout and login."
	email=request.cookies.get('id')
	filehash=bleach.clean(request.form['filehash'])
	
	if not checkPreSign(email, filehash):
		return "Unauthorized"
	requested_data=['Name']
	data=getUserData(email, requested_data, requester=f'{get_productname(request)} Signer: Sign document {filehash}', parent=get_productname(request))
	datajson=json.loads(data)[0]
	name=datajson['name']
	claimant=datajson['claimant']
	# Create a new PDF with the signature information
	file_content = downloadFile(filehash)
	packet = BytesIO()
	can = canvas.Canvas(packet, pagesize=letter)
	# Add a graphic green tick to show document signed


	
    # URL to tick image
	tick_image_url = "https://mauthn.mukham.in/logo.png"
	tick_image_response = requests.get(tick_image_url)
	if tick_image_response.status_code == 200:
		tick_image = Image.open(BytesIO(tick_image_response.content))
		can.drawImage(ImageReader(tick_image), 450, 650, width=50, height=50)
	
	tick_image_url = f"https://mauthn.mukham.in/dfp.png?parent={get_productname(request)}"
	tick_image_response = requests.get(tick_image_url)
	if tick_image_response.status_code == 200:
		tick_image = Image.open(BytesIO(tick_image_response.content))
		can.drawImage(ImageReader(tick_image), 250, 650, width=170, height=50)
	
	reqemail=getPreSignUploader(filehash, email)
	reqname=getNameFromEmail(reqemail)
	ptr=600
    # Draw signature image
	can.drawString(100, ptr, f"Signed by {name} ({email})")
	ptr=ptr-15
	can.drawString(100, ptr, f"Requested by: {reqname} ({reqemail})")

    # Split long text into multiple lines
	max_width = 80  # Maximum width before wrapping
	text1 = f"Verification {claimant}"
	wrapped_text1 = '\n'.join([text1[i:i+max_width] for i in range(0, len(text1), max_width)])
	strsplit=wrapped_text1.split('\n')
	ptr=ptr-15
	for part in strsplit:
		can.drawString(100, ptr, part)
		ptr=ptr-15

	text2 = f"Original file hash {filehash}"
	wrapped_text2 = '\n'.join([text2[i:i+max_width] for i in range(0, len(text2), max_width)])
	strsplit=wrapped_text2.split('\n')
	ptr=ptr-15
	for part in strsplit:
		can.drawString(100, ptr, part)
		ptr=ptr-15
	
	ptr=ptr-15
	current_time = datetime.now(tz=tz).strftime("%Y-%m-%d %H:%M:%S")
	can.drawString(100, ptr, f"Signed on {current_time}")

	ptr=ptr-15
	can.drawString(100, ptr, "Signature can be verified by requester and signer at anytime from the dashboard")

	ptr=ptr-100

	tick_image_url = "https://mauthn.mukham.in/sign.png"
	tick_image_response = requests.get(tick_image_url)
	if tick_image_response.status_code == 200:
		tick_image = Image.open(BytesIO(tick_image_response.content))
		can.drawImage(ImageReader(tick_image), 100, ptr, width=50, height=50)

	signedimage=tick_image_response.content
	can.save()
	packet.seek(0)

    #return PdfReader(packet)

	new_pdf = PdfReader(packet)

	# Read the existing PDF
	existing_pdf = PdfReader(BytesIO(file_content))
	output = PdfWriter()

	# Add the new page with the signature information
	output.add_page(new_pdf.pages[0])

	# Add all the original pages
	for page_num in range(len(existing_pdf.pages)):
		
		currentpage=existing_pdf.pages[page_num]
		currentpage = existing_pdf.pages[page_num]
		mediabox = currentpage.mediabox
		page_width = mediabox.upper_right[0] - mediabox.lower_left[0]
		page_height = mediabox.upper_right[1] - mediabox.lower_left[1]
		print("Width: ", page_width)
		print("Height: ", page_height)
		pack=BytesIO()
		can2 = canvas.Canvas(pack, pagesize=(page_width, page_height))
		tick_image=Image.open(BytesIO(signedimage))
		can2.drawImage(ImageReader(tick_image), int(page_width)-60, 10, width=50, height=50)
		can2.drawString(int(page_width)-200, 70, f"Signed by {name}")
		can2.drawString(int(page_width)-200, 85, f"Signed on {current_time}")
		can2.setLineWidth(1)
		can2.rect(int(page_width)-205, 5, 200, 90, stroke=1, fill=0)
		can2.save()
		pack.seek(0)
		temppdf=PdfReader(pack)
		currentpage.merge_page(temppdf.pages[0])
		output.add_page(currentpage)

	output.add_page(new_pdf.pages[0])

	# Write the output to a new PDF file
	output_stream = BytesIO()
	output.write(output_stream)
	output_stream.seek(0)
	newfile=output_stream.read()

	packet3=BytesIO(newfile)
	w = IncrementalPdfFileWriter(packet3)
	out = signers.sign_pdf(w, signers.PdfSignatureMetadata(field_name=f'Signature of {name}'), signer=cms_signer,)

	newfile=out.read()

	new_file_hash = hashlib.sha256(newfile).hexdigest()
	# Upload the signed PDF
	uploadFile(newfile, new_file_hash)
	uploader=getPreSignUploader(filehash, email)
	title=getPreSignTitle(filehash)
	addPostSign(uploader, filehash, new_file_hash, title, email)
	removePreSign(uploader, filehash, email)
	signCompleteMail(uploader, title, email,getproductname_link(request))
	return "File signed successfully"

@app.route("/all_signs_requested", methods=["GET", "POST"])
def all_signs_requested():
	if request.cookies.get('authorization') != 'signerauthorized':
		return "Session expired. Please logout and login."
	email=request.cookies.get('id')
	return jsonify(getAllSignsRequested(email))

@app.route("/all_sign_requests", methods=["GET", "POST"])
def all_sign_requests():
	if request.cookies.get('authorization') != 'signerauthorized':
		return "Session expired. Please logout and login."
	email=request.cookies.get('id')
	return jsonify(getAllSignRequests(email))

@app.route("/all_signed_by_me", methods=["GET", "POST"])
def all_signed_by_me():
	if request.cookies.get('authorization') != 'signerauthorized':
		return "Session expired. Please logout and login."
	email=request.cookies.get('id')
	return jsonify(getAllSignedMe(email))

@app.route("/all_signed", methods=["GET", "POST"])
def all_signed():
	if request.cookies.get('authorization') != 'signerauthorized':
		return "Session expired. Please logout and login."
	email=request.cookies.get('id')
	return jsonify(getAllSigned(email))

@app.route("/signverifypage", methods=["GET", "POST"])
def signverifypage():
	return render_template("signverify.html", productname=get_productname(request))

@app.route("/signverify", methods=["GET", "POST"])
def signverify():
	file = request.files['file']
	file_content = file.read()
	file_hash = hashlib.sha256(file_content).hexdigest()
	return getSignerPost(file_hash)

@app.route("/dashboardlogout", methods=["GET", "POST"])
def dashboardlogout():
	resp=make_response(render_template("adminlogout.html", productname=get_productname(request)))
	resp.set_cookie('authorization','unauthorized')
	return resp

@app.route("/promoteadmin", methods=["GET", "POST"])
def promoteadmin():
	if request.cookies.get('authorization') != 'authorized':
		return "Session expired. Please logout and login."
	email=bleach.clean(request.form['email'])
	if not checkUserExist(email):
		return email+" is not a valid user. User needs to complete sign up first."
	id=str(uuid.uuid4())
	addAdmin(id, email)
	adminPromoteMail(email,getproductname_link(request))
	return email+" promoted to admin"

@app.route("/getfincode", methods=["GET","POST"])
def getfincode():
	if request.cookies.get('authorization') != 'authorized':
		return "Session expired. Please logout and login."
	fincode=str(uuid.uuid4())
	email=request.cookies.get('id')
	addFinauth(fincode, email)
	return fincode
	

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
	if request.cookies.get('authorization') != 'authorized':
		return redirect('/dashboardlogout')
	return render_template("admin_dashboard.html", productname=get_productname(request))

@app.route("/verifyemail", methods=["GET","POST"])
def vemail():
	return "Redirecting to app"
@app.route("/logout",methods=["GET","POST"]) #parameter= token,id
def userlogout():
	token=bleach.clean(request.form['token'])
	id=bleach.clean(request.form['id'])
	if addLogout(id, token):
		return "success"
	else:
		return "failure"

@app.route("/login", methods=["GET","POST"]) #parameter = token
def login():
	token=bleach.clean(request.form['token'])
	try:
		id=getIdFromTokenSignin(token) #get from sign in table
		removeTokenFromSignin(token) #remove from signin table
		resp=make_response(id)
		resp.set_cookie('id', id)
		return resp
	except:
		return '0000'

@app.route("/req", methods=["GET","POST"]) #parameted = ID
def req():
	id=bleach.clean(request.form['id'])
	if id=='0' or id==0:
		if 'id' in request.cookies: 
			id=request.cookies.get('id')
	removeExpiredRequests(id,timeout)
	json=getRequestsFromID(id) #get from requests table
	resp=make_response(json)
	resp.headers.add('Access-Control-Allow-Origin', '*')
	return resp

@app.route("/logs", methods=["GET","POST"]) #parameted = ID
def logs():
	id=bleach.clean(request.form['id'])
	if id=='0' or id==0:
		if 'id' in request.cookies: 
			id=request.cookies.get('id')
	json=getLogsFromID(id) #get from logs table
	return json
		

@app.route("/face", methods=["GET", "POST"]) #parameter = request token, img in B64, location as string
def face():
	token=bleach.clean(request.form['token'])
	img=bleach.clean(request.form['img'])
	loc=request.remote_addr+' '+bleach.clean(request.form['location'])
	if request.headers.getlist("X-Forwarded-For"):
		loc = request.headers.getlist("X-Forwarded-For")[0]
	id=getIdFromToken(token) #get from Requests table
	imgblob=getImgBlobFromId(id) #Get from userstable
	img_orig=getImageFromBlob(imgblob) 
	vldty=facial_recognition(img,img_orig)
	if 'match' in vldty and vldty['match']:
		return 'false'
	# face_match_score = vldty
	updateGrantedPerms(token, 'face', loc) #Update requests table
	gc.collect()
	return 'true'
		
@app.route("/fido_platform", methods=["GET","POST"]) #parameter = request token
def fido_platform():
	token=bleach.clean(request.args.get('token'))
	requester=getRequesterFromToken(token)
	forward=find_intent(requester)
	return render_template("fidoauthn.html", token=token, type="platform", requester=requester, forward=forward, productname=get_productname(request))
	
@app.route("/api/authenticate_platform/begin", methods=["GET","POST"]) #parameter = token
def authenticate_platform_begin():
    token=bleach.clean(request.args.get('token'))
    id=getIdFromToken(token) #Get from requests table
    blob=getPlatformBlobFromId(id) #Get from Users table
    credentials=read_key(blob)
    if not credentials:
        abort(404)

    auth_data, state = server.authenticate_begin(credentials)
    session["state"] = state
    return cbor.encode(auth_data)
    
@app.route("/api/authenticate_platform/complete", methods=["GET","POST"]) #parameter =token
def authenticate_platform_complete():
    token=bleach.clean(request.args.get('token'))
    id=getIdFromToken(token) #Get from requests table
    blob=getPlatformBlobFromId(id) #Get from Users table
    credentials=read_key(blob) 
    if not credentials:
        abort(404)
    data = cbor.decode(request.get_data())
    credential_id = data["credentialId"]
    client_data = ClientData(data["clientDataJSON"])
    auth_data = AuthenticatorData(data["authenticatorData"])
    signature = data["signature"]
    print("clientData", client_data)
    print("AuthenticatorData", auth_data)

    server.authenticate_complete(
        session.pop("state"),
        credentials,
        credential_id,
        client_data,
        auth_data,
        signature,
    )
    print("ASSERTION OK")
    #geoloc=bleach.clean(request.args.get('geolocation'))
    loc=request.remote_addr   #+' '+geoloc
    #print('LOCATION FOUND '+geoloc)
    updateGrantedPerms(token, 'platform',loc) #Update Requests table
    return 'success'
    
@app.route("/fido_platform_verify", methods=["GET","POST"])
def fido_platform_verify(): #parameter=token GET
	token=bleach.clean(request.form['token'])
	p=checkGrantedPerms(token,'platform') #From Requests table
	if p:
		return 'true'
	else:
		if checkTokenExistRequests(token):
			return 'pending'
		else:
			if checkTokenExistLog(token):
				return 'true'
			else:
				return 'false'
		
@app.route("/fido_roaming", methods=["GET","POST"]) #parameter = request token
def fido_roaming():
	token=bleach.clean(request.args.get('token'))
	requester=getRequesterFromToken(token)
	forward=find_intent(requester)
	return render_template("fidoauthn.html", token=token, type="roaming", requester=requester, forward=forward, productname=get_productname(request))
	
@app.route("/api/authenticate_roaming/begin", methods=["GET","POST"]) #parameter = token
def authenticate_roaming_begin():
    token=bleach.clean(request.args.get('token'))
    id=getIdFromToken(token) #Get from requests table
    blob=getRoamingBlobFromId(id) #Get from Users table
    credentials=read_key(blob)
    if not credentials:
        abort(404)

    auth_data, state = server.authenticate_begin(credentials, user_verification="discouraged")
    session["state"] = state
    return cbor.encode(auth_data)
    
@app.route("/api/authenticate_roaming/complete", methods=["GET","POST"]) #parameter =token
def authenticate_roaming_complete():
    token=bleach.clean(request.args.get('token'))
    id=getIdFromToken(token) #Get from requests table
    blob=getRoamingBlobFromId(id) #Get from Users table
    credentials=read_key(blob)
    if not credentials:
        abort(404)
    data = cbor.decode(request.get_data())
    credential_id = data["credentialId"]
    client_data = ClientData(data["clientDataJSON"])
    auth_data = AuthenticatorData(data["authenticatorData"])
    signature = data["signature"]
    print("clientData", client_data)
    print("AuthenticatorData", auth_data)

    server.authenticate_complete(
        session.pop("state"),
        credentials,
        credential_id,
        client_data,
        auth_data,
        signature,
    )
    print("ASSERTION OK")
    
    #geoloc=bleach.clean(request.args.get('geolocation'))
    loc=request.remote_addr  #+' '+geoloc
    #print('LOCATION FOUND '+geoloc)
    updateGrantedPerms(token, 'roaming', loc) #Update Requests table
    return 'success'


@app.route("/cli/authenticate_roaming/begin", methods=["GET","POST"]) #parameter = token
def authenticate_roaming_begin2():
    token=bleach.clean(request.args.get('token'))
    id=getIdFromToken(token) #Get from requests table
    blob=getRoamingBlobFromId(id) #Get from Users table
    credentials=read_key(blob)
    if not credentials:
        abort(404)

    auth_data, state = server.authenticate_begin(credentials, user_verification="discouraged")
    session["state"] = state
    temp=base64.b64encode(pickle.dumps(auth_data)).decode()
    #temp2=pickle.loads(base64.b64decode(temp.encode()))
    #print(temp2)
    return temp
    
@app.route("/cli/authenticate_roaming/complete", methods=["GET","POST"]) #parameter =token
def authenticate_roaming_complete2():
    token=bleach.clean(request.args.get('token'))
    id=getIdFromToken(token) #Get from requests table
    blob=getRoamingBlobFromId(id) #Get from Users table
    credentials=read_key(blob)
    if not credentials:
        abort(404)
    result=bleach.clean(request.form.get('result'))
    dat=pickle.loads(base64.b64decode(result.encode()))
    server.authenticate_complete(
        session.pop("state"),
        credentials,
        dat.credential_id,
        dat.client_data,
        dat.authenticator_data,
        dat.signature,
    )
    print("ASSERTION OK")
    loc=request.remote_addr
    updateGrantedPerms(token, 'roaming', loc) #Update Requests table
    return "success"
	
@app.route("/fido_roaming_verify", methods=["GET","POST"])
def fido_roaming_verify(): #parameter=token
	token=bleach.clean(request.form['token'])
	p=checkGrantedPerms(token,'roaming')#Check requests table
	if p:
		return 'true'
	else:
		if checkTokenExistRequests(token):
			return 'pending'
		else:
			if checkTokenExistLog(token):
				return 'true'
			else:
				return 'false'

@app.route("/get_iot", methods=["GET", "POST"]) #parameter id
def get_iot():
	id=bleach.clean(request.form['id'])
	if id=='0' or id==0:
		if 'id' in request.cookies: 
			id=request.cookies.get('id')
	iottoken=getIotFromId(id)
	return iottoken

@app.route("/update_totp", methods=["GET", "POST"])
def update_totp():
	id=bleach.clean(request.form['id'])
	service_name=bleach.clean(request.form['service_name'])
	account_label=bleach.clean(request.form['account_label'])
	secret_key=bleach.clean(request.form['secret_key'])
	issuer=bleach.clean(request.form['issuer'])
	period=bleach.clean(request.form['period'])
	digits=bleach.clean(request.form['digits'])
	algorithm=bleach.clean(request.form['algorithm'])
	added_on=bleach.clean(request.form['added_on'])
	addToTotp(id, service_name, account_label, secret_key, issuer, period, digits, algorithm, added_on)
	return 'true'

@app.route("/get_totp", methods=['GET','POST'])
def get_totp():
	id=bleach.clean(request.form['id'])
	jsn=getTotpFromID(id)
	return jsn

@app.route("/del_totp", methods=['GET', 'POST'])
def del_totp():
	id=bleach.clean(request.form['id'])
	secret_key=bleach.clean(request.form['secret_key'])
	res=delTotp(id, secret_key)
	return res


@app.route("/add_request_fin", methods=["GET","POST"]) #parameters email, requested-data
def add_request_fintech():
	token=str(uuid.uuid4())
	authcode=request.headers['authorizationcode']
	authemail=getFinauth(authcode)
	if authemail=='0000':
		resp=make_response('Unauthorized request')
		resp.headers.add('Access-Control-Allow-Origin', '*')
		return resp
	email=bleach.clean(request.form['email'])
	reqdata=bleach.clean(request.form['data'])
	id='0000'
	if '@' in email:
		id=getIdFromEmail(email) #get from Users table
	else:
		id=getIdFromIot(email)
	if id=='0000':
		resp=make_response('0000')
		resp.headers.add('Access-Control-Allow-Origin', '*')
		return resp
	requester=bleach.clean(request.form['requester'])
	if  request is None or requester=='':
		requester=request.host
	ip=''
	if request.headers.getlist("X-Forwarded-For"):
		ip = str(request.headers.getlist("X-Forwarded-For")[0])
	else:
		ip = str(request.remote_addr)
	if 'mauthn.mukham.in' in requester or 'emauth.mukham.in' in requester:
		requester="Native application at "+ip
	ts=int(time.time())
	requester=requester+" - "+ip+getStatus(ip, product=get_productname(request))+" - Authorized by "+authemail
	addToRequest(token,id,requester,ts,reqdata,ip) #Insert to requests table
	eml2=getEmailFromId(id)
	sendNewReqMail(eml2, requester,getproductname_link(request))
	resp=make_response(token)
	resp.headers.add('Access-Control-Allow-Origin', '*')
	return resp

@app.route("/add_request", methods=["GET","POST"]) #parameters email, requested-data
def add_request():
	token=str(uuid.uuid4())
	email=bleach.clean(request.form['email'])
	reqdata=bleach.clean(request.form['data'])
	id='0000'
	if '@' in email:
		id=getIdFromEmail(email) #get from Users table
	else:
		id=getIdFromIot(email)
	if id=='0000':
		resp=make_response('0000')
		resp.headers.add('Access-Control-Allow-Origin', '*')
		return resp
	requester=bleach.clean(request.form['requester'])
	if  request is None or requester=='':
		requester=request.host
	ip=''
	if request.headers.getlist("X-Forwarded-For"):
		ip = str(request.headers.getlist("X-Forwarded-For")[0])
	else:
		ip = str(request.remote_addr)
	if 'mauthn.mukham.in' in requester or 'emauth.mukham.in' in requester:
		requester="Native application at "+ip
	ts=int(time.time())
	requester=requester+" - "+ip+getStatus(ip, product=get_productname(request))
	addToRequest(token,id,requester,ts,reqdata,ip) #Insert to requests table
	eml2=getEmailFromId(id)
	sendNewReqMail(eml2, requester,getproductname_link(request))
	resp=make_response(token)
	resp.headers.add('Access-Control-Allow-Origin', '*')
	return resp

@app.route("/get_data", methods=["GET","POST"]) #parameter token
def get_data():
	token=bleach.clean(request.form['token'])
	ts1=getTimeStampFromToken(token) #Get from requests table
	ts2=int(time.time())
	deltats=abs(ts2-ts1)
	ip=''
	if request.headers.getlist("X-Forwarded-For"):
		ip = str(request.headers.getlist("X-Forwarded-For")[0])
	else:
		ip = str(request.remote_addr)
	ip2=getIPFromToken(token)
	if not ip==ip2:
		print(ip)
		print(ip2)
		resp=make_response('expired')
		print(ts2,ts1,deltats) #Debug
		resp.headers.add('Access-Control-Allow-Origin', '*')
		return resp
	
	if deltats>timeout:
		remove_request(token) #Delete from requests table
		resp=make_response('expired')
		print(ts2,ts1,deltats) #Debug
		resp.headers.add('Access-Control-Allow-Origin', '*')
		return resp
	gperms=getGrantedPerms(token) #Get from requests table
	id=getIdFromToken(token) #Get from requests table
	aperms=getAuthnPerms(id) #Get from Users table
	if gperms==aperms and (not aperms=='000'): 
		reqdata=getReqData(token) #Get from requests table
		loc=move_to_log_preprocess_loc(token, id, product=get_productname(request))
		eml2=getEmailFromId(id)
		res=getResponse(reqdata, id, token, loc, eml2) #Get from users table, location from requests
		requester=getRequesterFromToken(token)
		
		
		move_to_log(token, id, loc)
		sendSuccessReqMail(eml2, requester,getproductname_link(request))
		resp=make_response(res)
		resp.headers.add('Access-Control-Allow-Origin', '*')
		return resp
	resp=make_response('pending')
	resp.headers.add('Access-Control-Allow-Origin', '*')
	return resp
@app.route("/check_logout",methods=["GET","POST"]) #Parameters token and id
def check_logout():
	token=bleach.clean(request.form['token'])
	
	if checkLogout(token):
		resp=make_response( "Logout successful")
		resp.headers.add('Access-Control-Allow-Origin','*')
		return resp
	else:
		resp=make_response("Logout unsuccessful")
		resp.headers.add('Access-Control-Allow-Origin','*')
		return resp

def move_to_log_preprocess_loc(token, id, product='MAuthN'):
	loc=getLocationFromToken(token)
	loc=loc+" - "+getStatus(loc, product=product)
	aperms=getAuthnPerms(id)
	loc=loc+" - "+permToString(aperms)
	return loc

def move_to_log(token, id, loc):
	requester=getRequesterFromToken(token) #Get from Requests table
	dtm=datetime.now(tz=tz).strftime("%Y/%m/%d %H:%M:%S")
	addToLogs(token,id,requester,dtm,loc) #Add to logs table
	remove_request(token) #Delete from Requests table
	
@app.route("/register", methods=["GET","POST"])
def register():
	#if request.cookies.get('authorization') != 'authorized':
	#	return redirect('/dashboardlogout')
	return render_template("register.html", productname=get_productname(request))
	
@app.route("/register_user", methods=["GET","POST"]) #Parameters email name dob
def register_user():
	#if request.cookies.get('authorization') != 'authorized':
	#	return redirect('/dashboardlogout')	
	email=bleach.clean(request.form['email'])
	name=bleach.clean(request.form['name'])
	dob=bleach.clean(request.form['dob'])
	id=str(uuid.uuid4())
	imgblob=str(uuid.uuid4())
	platformfidoblob=str(uuid.uuid4())
	roamingfidoblob=str(uuid.uuid4())
	authnperms='000'
	addToUsers(id,email,name,dob,imgblob,platformfidoblob,roamingfidoblob,authnperms) #Add to users table
	token=str(uuid.uuid4())
	addToSignUp(id,token) #Add to sign up table
	sendSignupEmail(email,token,getproductname_link(request))
	gc.collect()
	return redirect("/close_browser")
	
@app.route("/email_signup_user", methods=["GET","POST"])
def email_signup_user():
	token=bleach.clean(request.args.get("token"))
	return render_template("getcreds.html",token=token, productname=get_productname(request))

@app.route("/sign_in_token", methods=["GET","POST"]) #Parameter token of signup
def sign_in_token():
	get_productname(request)
	suptoken=bleach.clean(request.form['token'])
	id=getIdFromSignUpToken(suptoken) #Get from sign up table
	token=str(uuid.uuid4())[:5]
	addToSignIn(token,id) #Add to sign in table
	email=getEmailFromId(id)
	sendEmail(email,token,getproductname_link(request))
	return token

@app.route("/get_token_email", methods=["GET","POST"]) #Parameter email
def get_token_email():
	get_productname(request)
	email=bleach.clean(request.form['email'])
	token=str(uuid.uuid4())[:5]
	id=getIdFromEmail(email)
	if id=="0000":
		return "No user found"
	else:
		addToSignIn(token,id)
		sendEmail(email,token,getproductname_link(request))
		return "Email sent"
	
@app.route("/email-login", methods=["GET","POST"])
def email_login():
	return render_template("email_login.html", productname=get_productname(request))

@app.route("/add_image", methods=["GET","POST"]) #GET Parameters token, POST img in b64
def add_image():
	token=bleach.clean(request.args.get('token'))
	id=getIdFromSignUpToken(token) #Get from sign up table
	img=bleach.clean(request.form['img'])
	#if not facial_nospoof(img):
	#	return 'false'
	blob=getImgBlobFromId(id)
	try:
		saveImageToBlob(blob,img) 
		enableAuthnPerms(id,'face') #Update users table
		return 'true'
	except:
		return 'false'

@app.route("/api/register_platform/begin", methods=["GET","POST"]) #GET Parameter token
def register_platform_begin():
    token=bleach.clean(request.args.get('token'))
    id=getIdFromSignUpToken(token) #Get from sign up table
    uname=getEmailFromId(id) #Get from users table
    blob=getPlatformBlobFromId(id) #Get from Users table
    credentials=read_key(blob)
    registration_data, state = server.register_begin(
        {
            "id": (f'{get_productname(request)}_User').encode(),
            "name": uname,
            "displayName": uname,
            "icon": "https://example.com/image.png",
        },
        credentials,
        user_verification="discouraged",
        authenticator_attachment="platform",
    )
    session["state"] = state
    print("\n\n\n\n")
    print(registration_data)
    print("\n\n\n\n")
    return cbor.encode(registration_data)

@app.route("/api/register_platform/complete", methods=["GET","POST"]) #GET Parameter token
def register_platform_complete():
    token=bleach.clean(request.args.get('token'))
    id=getIdFromSignUpToken(token) #Get from sign up table
    blob=getPlatformBlobFromId(id) #Get from Users table
    credentials=read_key(blob)
    data = cbor.decode(request.get_data())
    client_data = ClientData(data["clientDataJSON"])
    att_obj = AttestationObject(data["attestationObject"])
    print("clientData", client_data)
    print("AttestationObject:", att_obj)
    auth_data = server.register_complete(session["state"], client_data, att_obj)
    credentials.append(auth_data.credential_data)
    save_key(blob, credentials)
    print("REGISTERED CREDENTIAL:", auth_data.credential_data)
    enableAuthnPerms(id,'platform') #Update users table
    return cbor.encode({"status": "OK"})
    
@app.route("/api/register_roaming/begin", methods=["GET","POST"]) #GET Parameter token
def register_roaming_begin():
    token=bleach.clean(request.args.get('token'))
    id=getIdFromSignUpToken(token) #Get from sign up table
    uname=getEmailFromId(id) #Get from users table
    blob=getRoamingBlobFromId(id) #Get from Users table
    credentials=read_key(blob)
    registration_data, state = server.register_begin(
        {
            "id": (f'{get_productname(request)}_User').encode(),
            "name": uname,
            "displayName": uname,
            "icon": "https://example.com/image.png",
        },
        credentials,
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )
    session["state"] = state
    print("\n\n\n\n")
    print(registration_data)
    print("\n\n\n\n")
    return cbor.encode(registration_data)

@app.route("/api/register_roaming/complete", methods=["GET","POST"]) #GET Parameter token
def register_roaming_complete():
    token=bleach.clean(request.args.get('token'))
    id=getIdFromSignUpToken(token) #Get from sign up table
    blob=getRoamingBlobFromId(id) #Get from Users table
    credentials=read_key(blob)
    data = cbor.decode(request.get_data())
    client_data = ClientData(data["clientDataJSON"])
    att_obj = AttestationObject(data["attestationObject"])
    print("clientData", client_data)
    print("AttestationObject:", att_obj)
    auth_data = server.register_complete(session["state"], client_data, att_obj)
    credentials.append(auth_data.credential_data)
    save_key(blob, credentials)
    print("REGISTERED CREDENTIAL:", auth_data.credential_data)
    enableAuthnPerms(id,'roaming') #Update users table
    return cbor.encode({"status": "OK"})

@app.route("/user_save", methods=["GET","POST"]) #GET Parameter token
def user_save():
	token=bleach.clean(request.args.get('token'))
	removeFromSignUp(token) #Remove from sign up table
	return redirect("/close_browser")
	
@app.route("/close_browser", methods=["GET","POST"])
def close_browser():
	if 'intent' not in request.args or request.args.get('intent')==None or request.args.get('intent')=='':
		return render_template("close.html", productname=get_productname(request))
	else:
		return render_template('launch_intent.html', intent=bleach.clean(request.args.get('intent')), productname=get_productname(request))

@app.route("/sdk/verifyUser", methods=["GET","POST"])
def sdk_verifyUser():
	email_of_user=bleach.clean(request.form['email_of_user'])
	requester=bleach.clean(request.form['requester'])
	return str(verifyUser(email_of_user,requester, parent=get_productname(request)))

@app.route("/sdk/getUserData", methods=["GET","POST"])
def sdk_getUserData():
	email_of_user=bleach.clean(request.form['email_of_user'])
	req_data=bleach.clean(request.form['requested_data'])
	x = req_data.split(",")
	requested_data = [s.strip() for s in x]
	requester=bleach.clean(request.form['requester'])
	return str(getUserData(email_of_user,requested_data,requester, parent=get_productname(request)))

@app.route("/modify_user", methods=["GET","POST"])
def modify_user():
	if request.cookies.get('authorization') != 'authorized':
		return redirect('/dashboardlogout')	
	return render_template("modify_user.html", productname=get_productname(request))

@app.route("/modify", methods=["GET","POST"])
def usermodify():
	if request.cookies.get('authorization') != 'authorized':
		return "Session expired. Please logout and login."
	email=bleach.clean(request.form['email'])
	if checkUserExist(email):
		account_modify(email)
		return "Email sent"
	else:
		return "User doesn't exist"

@app.route("/getlogcount", methods=["GET", "POST"])
def getlogcount():
	return logCount()

@app.route("/reboot", methods=["GET","POST"])
def reboot_server():
	try:
		action=bleach.clean(request.form['action'])
		if action=='reboot_server':
			os.system('sudo reboot')
			return ""
		else:
			return "Reboot not authorized"
		return "Reboot failed"
	except:
		return "Reboot failed"
	
@app.route("/sdkdocs", methods=['GET', 'POST'])
def sdkdocs():
	return redirect(f'https://emauthsdk.indominuslabs.in')

@app.route("/appupdate", methods=['POST'])
def appudpateavail():
	check=bleach.clean(request.form.get('securitycheck'))
	if check!='appupdatecheck':
		return 'Invalid'
	emaillist=get_recent_user_emails(months=recentmonths)
	#appUpdate(emaillist,getproductname_link(request))
	return 'Sent'

allowed_scopes=['profile', 'email', 'openid', 'user:email', 'read', 'user.info']

@app.route("/oauth/authorize", methods=["GET"])
def oidc_authorize():
	response_type=bleach.clean(request.args.get('response_type'))
	if response_type != 'code':
		respx= make_response(jsonify({'error':'invalid response_type'}), 400)
		respx.headers.add('Access-Control-Allow-Origin', '*')
		return respx
	redirect_uri=bleach.clean(request.args.get('redirect_uri'))
	scope=bleach.clean(request.args.get('scope')).split()
	client=bleach.clean(request.args.get('client_id', 'Unknown client'))
	scope_correct=False
	for s in scope:
		if s in allowed_scopes:
			scope_correct=True
	
	if not scope_correct:
		respx= make_response(jsonify({'error':'invalid scope'}), 400)
		respx.headers.add('Access-Control-Allow-Origin', '*')
		return respx
	state=bleach.clean(request.args.get('state','default'))
	nonce=bleach.clean(request.args.get('nonce','12345'))
	
	respx=make_response(render_template('oidc_login.html', client=client, state=state, nonce=nonce, redirecturi=redirect_uri), productname=get_productname(request))
	respx.headers.add('Access-Control-Allow-Origin', '*')
	return respx
	
@app.route("/oauth/login", methods=["POST"])
def oidc_login():
	email=bleach.clean(request.form.get('email'))
	state=bleach.clean(request.form.get('state'))
	nonce=bleach.clean(request.form.get('nonce'))
	redirect_uri=bleach.clean(request.form.get('redirecturi'))
	requested_data=['Name', 'Date-Of-Birth', 'Image']
	print(requested_data)
	data= verifyUser(email, requester=f'{get_productname(request)} OAuth')
	print(data)
	
	if not data:
		callback_uri=f'{redirect_uri}?error=unauthorized&nonce={nonce}&state={state}'	
		respx=make_response(redirect(callback_uri), 403)
		respx.headers.add('Access-Control-Allow-Origin', '*')
		return respx
	user=getIdFromEmail(email)
	print(user)
	authzcode=addOIDCCode(user, state)
	print("AUTHZ ", authzcode)
	callback_uri=f'{redirect_uri}?code={authzcode}&nonce={nonce}&state={state}'
	respx=make_response(redirect(callback_uri))
	respx.headers.add('Access-Control-Allow-Origin', '*')
	return respx
	
@app.route("/oauth/token", methods=["POST"])
def oidc_token():
	try:
		grant_type=bleach.clean(request.form.get('grant_type'))
		if grant_type=='authorization_code':
			code=bleach.clean(request.form.get('code'))
			access_token, refresh_token=addOIDCTokenCode(code)
			if access_token=='0000':
				respx=make_response(jsonify({'error':'unauthorized'}), 403)
				respx.headers.add('Access-Control-Allow-Origin', '*')
				return respx
			ret={}
			ret['access_token']=access_token
			ret['refresh_token']=refresh_token
			ret['expire']=oidc_exp
			respx=make_response(jsonify(ret))
			respx.headers.add('Access-Control-Allow-Origin', '*')
			return respx
		if grant_type=='refresh_token':
			refresh_token=bleach.clean(request.form.get('refresh_token'))
			access_token=addOIDCTokenRefresh(refresh_token)
			if access_token=='0000':
				respx=make_response(jsonify({'error':'unauthorized'}), 403)
				respx.headers.add('Access-Control-Allow-Origin', '*')
				return respx
			ret={}
			ret['access_token']=access_token
			ret['expire']=oidc_exp
			respx=make_response(jsonify(ret))
			respx.headers.add('Access-Control-Allow-Origin', '*')
			return respx
		respx=make_response(jsonify({'error':'invalid grant_type'}), 400)
		respx.headers.add('Access-Control-Allow-Origin', '*')
		return respx
	except:
		respx=make_response(jsonify({'error':'unauthorized'}), 403)
		respx.headers.add('Access-Control-Allow-Origin', '*')
		return respx
	
@app.route("/oauth/revoke", methods=['POST'])
def oidc_revoke():
	access_token=bleach.clean(request.form.get('access_token','0000'))
	revokeTokenOIDC(access_token)
	respx=make_response(jsonify({'message':'token revoked'}))
	respx.headers.add('Access-Control-Allow-Origin', '*')
	return respx
	
@app.route("/userinfo", methods=["GET", "POST"])
def oidc_userinfo():
	print(request.headers)
	authheader=request.headers.get('Authorization', 'none')
	print(authheader)
	if not authheader.startswith('Bearer '):
		respx=make_response(jsonify({'error':'unauthorized'}), 403)
		respx.headers.add('Access-Control-Allow-Origin', '*')
		return respx
	auth_token=authheader[len('Bearer '):]
	print(auth_token)
	userdata=getUserDetailsOIDC(auth_token)
	if userdata=='0000':
		respx=make_response(jsonify({'error':'unauthorized'}), 403)
		respx.headers.add('Access-Control-Allow-Origin', '*')
		return respx
	respx=make_response(jsonify(json.loads(userdata)))
	respx.headers.add('Access-Control-Allow-Origin', '*')
	return respx

@app.route("/userimage", methods=["GET", "POST"])
def oidc_userimage():
	authheader=request.headers.get('authorization', 'none')
	if not authheader.startswith('Bearer '):
		respx=make_response(jsonify({'error':'unauthorized'}), 403)
		respx.headers.add('Access-Control-Allow-Origin', '*')
		return respx
	auth_token=authheader[len('Bearer '):]
	userdata=getUserImageOIDC(auth_token)
	if userdata=='0000':
		respx=make_response(jsonify({'error':'unauthorized'}), 403)
		respx.headers.add('Access-Control-Allow-Origin', '*')
		return respx
	respx=make_response(jsonify(json.loads(userdata)))
	respx.headers.add('Access-Control-Allow-Origin', '*')
	return respx

@app.route("/idverifier", methods=["GET", "POST"])
def idverifier():
	return render_template("idverifier.html", productname=get_productname(request))

@app.route('/appinfo', methods=['POST'])
def appinfo():
	userid=request.form['id']
	ret=getUserDetailsApp(userid)
	if ret=='0000':
		return json.dumps({'error':'User not found'})
	return ret

@app.route("/checkdomain", methods=['GET', 'POST'])
def check_domain():
	temp=str(uuid.uuid4())
	outf=open(filepth+'temp', 'w')
	outf.write(temp)
	outf.close()
	return temp

def account_modify(email):
	id=getIdFromEmail(email)
	token=str(uuid.uuid4())
	addToSignUp(id,token) #Add to sign up table
	sendSignupEmail(email,token,getproductname_link(request))
	   
def read_key(blob):
	try:
		binkey=downloadFile(blob) #Download from blob
		return binkey
	except:
		return []
		
def save_key(blob, credentials):
	uploadFile(credentials,blob) #Upload
	
def saveImageToBlob(blob, img):
	return uploadFile(img.encode(), blob)
	
def getImageFromBlob(blob):
	return downloadFile(blob).decode()

def permToString(perms):
	k="Authentication methods: "
	if perms[0]=='1':
		k=k+'Face recognition, '
	if perms[1]=='1':
		k=k+'Device attestation, '
	if perms[2]=='1':
		k=k+'Security key, '
	k=k[0:len(k)-2]
	return k
	
if __name__ == "__main__":

	app.run(ssl_context="adhoc", host='0.0.0.0', port=8080, debug=False)












