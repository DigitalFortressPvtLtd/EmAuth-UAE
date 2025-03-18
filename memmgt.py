import psutil
import gc
import os

def restart():
  mem=int(psutil.virtual_memory().free/1024)
  print("RAM Usage: ",mem)
  if mem<800000:
    print("Apache restarted")
    #os.system("sudo service apache2 restart")
