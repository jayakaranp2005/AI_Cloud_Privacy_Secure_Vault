"""
PrivaVault — Azure Blob Storage Service
Phase 1-2 | branch: feature/auth-upload

Responsibilities:
  - Upload encrypted file ciphertext to Azure Blob Storage
  - Download encrypted ciphertext back from Blob Storage
  - Generate unique blob names to prevent collisions
  - Handle connection errors gracefully

The service never sees raw file bytes — only ciphertext.
Only the routes know how to encrypt/decrypt (in services/encryption.py).
"""

import os
import uuid
from datetime import datetime, timedelta

from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from dotenv import load_dotenv

load_dotenv()

AZURE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
AZURE_CONTAINER_NAME = os.getenv("AZURE_BLOB_CONTAINER_NAME", "privavault-docs")


# ---------------------------------------------------------------------------
# Blob service initialization
# ---------------------------------------------------------------------------
def get_blob_client():
    """
    Returns an authenticated BlobServiceClient for Azure Blob Storage.
    
    Raises RuntimeError if AZURE_STORAGE_CONNECTION_STRING is not set in .env
    """
    if not AZURE_CONNECTION_STRING:
        raise RuntimeError(
            "AZURE_STORAGE_CONNECTION_STRING not set in environment. "
            "Check your .env file."
        )
    
    return BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)


def ensure_container_exists():
    """
    Checks if the container exists; creates it if needed.
    
    Should be called once at app startup (in main.py lifespan).
    """
    try:
        client = get_blob_client()
        container_client = client.get_container_client(AZURE_CONTAINER_NAME)
        
        # This raises an exception if the container doesn't exist
        container_client.get_container_properties()
        print(f"[PrivaVault] Blob container '{AZURE_CONTAINER_NAME}' exists.")
    except Exception as e:
        # Container doesn't exist — create it
        print(f"[PrivaVault] Creating blob container '{AZURE_CONTAINER_NAME}'...")
        try:
            client = get_blob_client()
            client.create_container(name=AZURE_CONTAINER_NAME)
            print(f"[PrivaVault] Blob container created successfully.")
        except Exception as create_error:
            print(f"[PrivaVault] ERROR creating container: {create_error}")
            raise


# ---------------------------------------------------------------------------
# Upload encrypted ciphertext to Blob Storage
# ---------------------------------------------------------------------------
def upload_to_blob(ciphertext: bytes, original_filename: str, user_id: int) -> str:
    """
    Uploads encrypted file bytes to Azure Blob Storage.
    
    Args:
        ciphertext (bytes): Encrypted file data (output from services/encryption.py)
        original_filename (str): Original filename for reference (not used in blob name)
        user_id (int): Owner's user ID (included in blob path for org)
    
    Returns:
        str: Full Blob Storage URL pointing to the uploaded ciphertext
    
    Raises:
        RuntimeError: If AZURE_STORAGE_CONNECTION_STRING is not set
        Exception: If Blob Storage upload fails
    
    Flow:
      1. Generate unique blob name: privavault/<user_id>/<uuid>.bin
      2. Upload ciphertext bytes to Blob Storage
      3. Return the blob's public URL
    
    The blob name includes user_id for logical organization (allows per-user queries).
    The UUID ensures no filename collisions even if the same file is uploaded twice.
    """
    try:
        # Generate unique blob name
        # Format: privavault/<user_id>/<uuid>.bin
        blob_name = f"privavault/{user_id}/{uuid.uuid4()}.bin"
        
        # Get blob client and upload
        client = get_blob_client()
        blob_client = client.get_blob_client(
            container=AZURE_CONTAINER_NAME,
            blob=blob_name
        )
        
        # Upload with metadata for debugging
        blob_client.upload_blob(
            ciphertext,
            overwrite=True,
            metadata={
                "user_id": str(user_id),
                "original_filename": original_filename,
                "uploaded_at": datetime.utcnow().isoformat(),
            }
        )
        
        # Return the blob URL
        blob_url = blob_client.url
        print(f"[PrivaVault] Uploaded ciphertext for user {user_id} to {blob_url}")
        return blob_url
    
    except Exception as e:
        print(f"[PrivaVault] ERROR uploading to Blob Storage: {e}")
        raise


# ---------------------------------------------------------------------------
# Download encrypted ciphertext from Blob Storage
# ---------------------------------------------------------------------------
def download_from_blob(blob_url: str) -> bytes:
    """
    Downloads encrypted ciphertext from Azure Blob Storage.
    
    Args:
        blob_url (str): Full URL to the blob (returned by upload_to_blob)
    
    Returns:
        bytes: Encrypted file data (ready to be decrypted by services/encryption.py)
    
    Raises:
        RuntimeError: If AZURE_STORAGE_CONNECTION_STRING is not set
        Exception: If Blob Storage download fails
    
    Flow:
      1. Parse blob name from URL
      2. Fetch blob data from Blob Storage
      3. Return raw bytes
    
    The ciphertext is downloaded into RAM temporarily and should be
    decrypted immediately and then wiped (the caller's responsibility).
    """
    try:
        client = get_blob_client()
        
        # Extract blob name from URL
        # URL format: https://accountname.blob.core.windows.net/container/blob_name
        blob_name = blob_url.split(f"{AZURE_CONTAINER_NAME}/")[-1]
        
        # Download blob
        blob_client = client.get_blob_client(
            container=AZURE_CONTAINER_NAME,
            blob=blob_name
        )
        
        download_stream = blob_client.download_blob()
        ciphertext = download_stream.readall()
        
        print(f"[PrivaVault] Downloaded ciphertext from {blob_url}")
        return ciphertext
    
    except Exception as e:
        print(f"[PrivaVault] ERROR downloading from Blob Storage: {e}")
        raise


# ---------------------------------------------------------------------------
# Optional: Generate a SAS URL for temporary blob access
# ---------------------------------------------------------------------------
def generate_sas_url(blob_url: str, expiry_hours: int = 1) -> str:
    """
    Generates a Shared Access Signature (SAS) URL for temporary blob access.
    
    Useful if you want to give clients direct read-only access to a blob
    without routing through the FastAPI server.
    
    Args:
        blob_url (str): Full URL to the blob
        expiry_hours (int): How long the SAS URL remains valid (default: 1 hour)
    
    Returns:
        str: SAS URL with embedded credentials
    
    Example usage (in download route):
        Instead of downloading and streaming through FastAPI,
        you could return a SAS URL directly to the client:
            return {"sas_url": generate_sas_url(blob_url)}
    
    The client then downloads directly from Blob Storage.
    """
    try:
        client = get_blob_client()
        
        # Extract blob name from URL
        blob_name = blob_url.split(f"{AZURE_CONTAINER_NAME}/")[-1]
        
        # Extract account name from connection string
        # Format: DefaultEndpointsProtocol=https;AccountName=xxx;AccountKey=yyy;...
        account_name = AZURE_CONNECTION_STRING.split("AccountName=")[1].split(";")[0]
        
        # Generate SAS token
        sas_token = generate_blob_sas(
            account_name=account_name,
            container_name=AZURE_CONTAINER_NAME,
            blob_name=blob_name,
            account_key=AZURE_CONNECTION_STRING.split("AccountKey=")[1].split(";")[0],
            permission=BlobSasPermissions(read=True),
            expiry=datetime.utcnow() + timedelta(hours=expiry_hours),
        )
        
        # Build SAS URL
        sas_url = f"{blob_url}?{sas_token}"
        return sas_url
    
    except Exception as e:
        print(f"[PrivaVault] ERROR generating SAS URL: {e}")
        raise


print("[PrivaVault] Blob Storage service initialized.")
