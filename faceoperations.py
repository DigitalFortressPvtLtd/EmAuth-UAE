import base64


def facial_recognition(imga1, imga2):
    print("Image 1: ", imga1)
    print("Image 2: ", imga2)
    return compare_faces(imga1, imga2)

    
#It is recommended to develop the pipelines in a seperate file
#Import the file here and call the proper functions	
import cv2
import base64
import numpy as np
import io
from PIL import Image

def decode_base64_image(b64_string):
    """Decodes a Base64 PNG string to a grayscale OpenCV image."""
    image_data = base64.b64decode(b64_string)
    image = Image.open(io.BytesIO(image_data)).convert("L")  # Convert to grayscale
    return np.array(image)

def train_face_recognizer(b64_image):
    """Trains LBPH recognizer on a single image."""
    recognizer = cv2.face.LBPHFaceRecognizer_create()
    image = decode_base64_image(b64_image)
    recognizer.train([image], np.array([0]))  # Train on one face
    return recognizer

def compare_faces(b64_image1, b64_image2, threshold=60):
    """Compares two images using LBPH recognizer."""
    recognizer = train_face_recognizer(b64_image1)
    image2 = decode_base64_image(b64_image2)
    label, confidence = recognizer.predict(image2)
    return confidence < threshold  # Returns True/False based on confidence score

