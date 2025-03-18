import os

# read from environment variables 
# ENDPOINT = os.environ.get("FACE_ENDPOINT")
# API_KEY = os.environ.get("FACE_API_KEY")
API_KEY = '7UXs67XlgfoQlteEjNV0hZTgtiOYEMhJXcrlnLKKFf2GpO3Nv0wSJQQJ99ALACGhslBXJ3w3AAAKACOGTBaR'
ENDPOINT = 'https://mauthn-face.cognitiveservices.azure.com/'


if ENDPOINT is None or API_KEY is None:
	raise ValueError("FACE_ENDPOINT and FACE_API_KEY environment variables must be set.")
