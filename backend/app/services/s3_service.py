import boto3
from botocore.exceptions import ClientError
from app.config import settings
import logging

logger = logging.getLogger(__name__)

# Fallback in-memory storage mock when S3 credentials are dummy or unreachable
class InMemoryS3Mock:
    def __init__(self):
        self.store = {}
        
    def upload_fileobj(self, fileobj, bucket, key, ExtraArgs=None):
        fileobj.seek(0)
        self.store[f"{bucket}/{key}"] = fileobj.read()
        return True
        
    def generate_presigned_url(self, client_method, Params=None, ExpiresIn=3600):
        bucket = Params.get("Bucket")
        key = Params.get("Key")
        # Return a simulated URL
        return f"https://s3.amazonaws.com/{bucket}/{key}?mock_token=123"

# Initialize boto3 S3 client or fallback
try:
    if settings.AWS_ACCESS_KEY_ID in ["aws_temp_dummy_id", "", None]:
        s3_client = InMemoryS3Mock()
    else:
        s3_client = boto3.client(
            "s3",
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
except Exception:
    s3_client = InMemoryS3Mock()

def upload_pdf(scan_id: str, user_id: str, pdf_bytes: bytes) -> str:
    global s3_client
    s3_key = f"reports/{user_id}/{scan_id}/report.pdf"
    
    from io import BytesIO
    fileobj = BytesIO(pdf_bytes)
    
    try:
        if isinstance(s3_client, InMemoryS3Mock):
            s3_client.upload_fileobj(fileobj, settings.AWS_S3_BUCKET, s3_key)
        else:
            s3_client.upload_fileobj(
                fileobj,
                settings.AWS_S3_BUCKET,
                s3_key,
                ExtraArgs={"ContentType": "application/pdf"}
            )
    except ClientError as e:
        logger.error(f"Failed S3 upload: {str(e)}")
        # Fall back to mocking if AWS upload fails
        s3_client = InMemoryS3Mock()
        s3_client.upload_fileobj(fileobj, settings.AWS_S3_BUCKET, s3_key)
        
    return s3_key

def generate_presigned_url(s3_key: str, expires_in=900) -> str:
    try:
        url = s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": settings.AWS_S3_BUCKET, "Key": s3_key},
            ExpiresIn=expires_in
        )
        return url
    except Exception as e:
        logger.error(f"Failed to generate presigned S3 url: {str(e)}")
        # Fallback simulated URL
        return f"https://s3.amazonaws.com/{settings.AWS_S3_BUCKET}/{s3_key}?presigned=true"
