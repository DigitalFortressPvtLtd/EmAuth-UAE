import pickle
from memmgt import *
import os


cachefolder='/etc/mauthn/files/'

def uploadFile(data, blob_id):
  fl=open(cachefolder+blob_id, 'wb')
  pickle.dump(data, fl)
  fl.close()
  
def downloadFile(blob_id):
  fl=open(cachefolder+blob_id, 'rb')
  return pickle.load(fl)

def deleteFile(blob_id):
  if os.path.exists(cachefolder+blob_id):
  	os.remove(cachefolder+blob_id)

def createContainers():
  try:
    os.system('sudo mkdir -p '+files)
    os.system('sudo echo hello > '+cachefolder+'sample')
    os.system('sudo chmod -R 777 /etc/mauthn')
  except:
    pass
  
def resetContainers():
  try:
    os.system('sudo rm -rf '+cachefolder)
  except:
    pass
  createContainers()
