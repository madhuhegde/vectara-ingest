import argparse
import json
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Default Google Drive folder ID (used when --folder-id is not specified)
DEFAULT_GDRIVE_FOLDER_ID = '1on0_l-Upv2up4zQbHXX0Jj3qg8H4Uw0h'


def check_access(folder_id: str, credentials_path: str = 'credentials.json'):
    # 1. Load the credentials from the file
    try:
        with open(credentials_path, 'r') as f:
            creds_data = json.load(f)
            
        # Create a Credentials object from your JSON data
        creds = Credentials(
            token=creds_data.get('token'),
            refresh_token=creds_data.get('refresh_token'),
            token_uri=creds_data.get('token_uri'),
            client_id=creds_data.get('client_id'),
            client_secret=creds_data.get('client_secret'),
            scopes=creds_data.get('scopes')
        )
    except Exception as e:
        print(f"❌ Error loading credentials: {e}")
        return

    # 2. Build the Drive Service
    try:
        service = build('drive', 'v3', credentials=creds)
        
        # 3. Attempt to get metadata for the specific folder
        # We explicitly ask for the 'name' field to prove we can read it.
        file = service.files().get(fileId=folder_id, fields='id, name').execute()
        
        print(f"✅ SUCCESS! You have access.")
        print(f"Folder Name: {file.get('name')}")
        print(f"Folder ID:   {file.get('id')}")

    except HttpError as error:
        # Handle specific HTTP errors
        if error.resp.status == 404:
            print("❌ FAILURE: File not found. The credentials are valid, but they do NOT have permission to view this specific folder.")
        elif error.resp.status == 403:
            print("❌ FAILURE: Permission denied. The user is not authorized.")
        elif error.resp.status == 401:
            print("❌ FAILURE: Authentication failed. The tokens might be expired or revoked.")
        else:
            print(f"❌ An error occurred: {error}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Check Google Drive OAuth credentials and folder access.',
    )
    parser.add_argument(
        '--folder-id',
        '-f',
        default=DEFAULT_GDRIVE_FOLDER_ID,
        metavar='FOLDER_ID',
        help=f'Google Drive folder ID to check (default: {DEFAULT_GDRIVE_FOLDER_ID})',
    )
    parser.add_argument(
        '--credentials',
        '-c',
        default='credentials.json',
        help='Path to credentials.json (default: credentials.json)',
    )
    args = parser.parse_args()
    check_access(args.folder_id, args.credentials)
