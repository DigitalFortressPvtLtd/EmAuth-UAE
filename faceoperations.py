import base64


def facial_recognition(imga1, imga2):
    print("Image 1: ", imga1)
    print("Image 2: ", imga2)
    return compare_faces(imga1, imga2)

    
#It is recommended to develop the pipelines in a seperate file
#Import the file here and call the proper functions	
import face_recognition
import numpy as np
import base64
import io
from PIL import Image

def decode_base64_image(b64_string):
    """Decodes a Base64 PNG string to a NumPy array."""
    image_data = base64.b64decode(b64_string)
    image = Image.open(io.BytesIO(image_data))
    return np.array(image)  # Returns image as NumPy array

def get_face_encoding(b64_string):
    """Extracts face encoding from Base64 image."""
    img = decode_base64_image(b64_string)
    face_locations = face_recognition.face_locations(img, model="hog")  # Use lightweight HOG
    if not face_locations:
        return None
    return face_recognition.face_encodings(img, face_locations)[0]

def compare_faces(b64_image1, b64_image2, threshold=0.6):
    """Compares two Base64-encoded images."""
    encoding1 = get_face_encoding(b64_image1)
    encoding2 = get_face_encoding(b64_image2)
    if encoding1 is None or encoding2 is None:
        return False
    distance = np.linalg.norm(encoding1 - encoding2)
    return distance < threshold  # Returns True/False

