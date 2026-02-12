import base64
import json
import requests
import datetime
import hashlib
import hmac
from dataclasses import dataclass
from typing import Optional

from awsco import AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_REGION, SERVICE, HOST, ENDPOINT

@dataclass
class Error:
    msg: str
    dev_msg: Optional[str] = None

    def __eq__(self, other):
        if isinstance(other, str):
            return self.msg == other
        return super().__eq__(other)


def get_image_data_from_base64(base64_str):
    """Convert base64 string to image bytes."""
    # Strip off the prefix data if present
    if base64_str.startswith("data:image"):
        base64_str = base64_str.split(",")[1]

    # Decode the base64 string
    image_data = base64.b64decode(base64_str)
    return image_data


def sign(key, msg):
    """Sign a message with a key using HMAC SHA256."""
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_signature_key():
    """Generate AWS signature key."""
    date_stamp = datetime.datetime.utcnow().strftime("%Y%m%d")
    key_date = sign(("AWS4" + AWS_SECRET_KEY).encode("utf-8"), date_stamp)
    key_region = sign(key_date, AWS_REGION)
    key_service = sign(key_region, SERVICE)
    key_signing = sign(key_service, "aws4_request")
    return key_signing


def create_headers(payload, date_stamp):
    """Create AWS authentication headers."""
    amz_date = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    signed_key = get_signature_key()

    # Create string-to-sign
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    canonical_request = f"POST\n/\n\nhost:{HOST}\n\nhost\n{payload_hash}"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{date_stamp}/{AWS_REGION}/{SERVICE}/aws4_request\n"
        + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    )

    # Generate signature
    signature = hmac.new(
        signed_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    # Authorization Header
    authorization_header = (
        f"AWS4-HMAC-SHA256 Credential={AWS_ACCESS_KEY}/{date_stamp}/{AWS_REGION}/{SERVICE}/aws4_request, "
        f"SignedHeaders=host, Signature={signature}"
    )

    return {
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Date": amz_date,
        "Authorization": authorization_header,
    }


def facial_recognition_aws(base64_img1, base64_img2):
    """Compare two faces using AWS Rekognition."""
    print("Processing images with AWS Rekognition...")

    try:
        # Prepare Payload with Base64 image data
        payload = json.dumps(
            {
                "SourceImage": {"Bytes": base64_img1},
                "TargetImage": {"Bytes": base64_img2},
            }
        )

        # Create Headers with Action
        date_stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
        headers = create_headers(payload, date_stamp)
        headers["X-Amz-Target"] = "RekognitionService.CompareFaces"

        # Send request to AWS Rekognition
        response = requests.post(ENDPOINT, headers=headers, data=payload)
        response_data = response.json()

        # Check for errors in response
        if "__type" in response_data:
            error_type = response_data["__type"]
            error_message = response_data.get("message", "Unknown error")
            print(f"AWS Error: {error_type} — {error_message}")
            return False


        # Check if match found
        if "FaceMatches" not in response_data or not response_data["FaceMatches"]:
            # Check if no faces were detected
            if "UnmatchedFaces" in response_data:
                print("Face not matched")
                return False
            print("No faces detected in one or both images.")
            return False


        confidence = response_data["FaceMatches"][0]["Similarity"]
        print(f"Face matched with confidence: {confidence:.2f}%")
        return True


    except requests.exceptions.RequestException as e:
        print(f"Network error occurred: {e}")
        return False
    except Exception as e:
        print(f"Unknown error occurred: {e}")
        return False

def facial_recognition(base64_img1, base64_img2):
    return True #Comment this line out when you fix the AWS
    #facial_recognition(base64_img1, base64_img2) #Uncomment this line after fixing the AWS
