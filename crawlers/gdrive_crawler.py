import io
import json
import logging
import os
import requests
from datetime import datetime, timedelta
from typing import List, Optional

import ray
from omegaconf import OmegaConf
from slugify import slugify

from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build, Resource
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload

from core.crawler import Crawler
from core.indexer import Indexer
from core.utils import setup_logging, safe_remove_file, get_docker_or_local_path

logger = logging.getLogger(__name__)

logging.getLogger('googleapiclient.http').setLevel(logging.ERROR)

SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]
SERVICE_ACCOUNT_FILE = '/home/vectara/env/credentials.json'

# Shared cache to keep track of files that have already been crawled
class SharedCache:
    def __init__(self):
        self.cache = set()

    def add(self, id: str):
        self.cache.add(id)

    def contains(self, id: str) -> bool:
        return id in self.cache

def get_credentials(delegated_user: str, config_path: str) -> service_account.Credentials:
    """Get service account credentials with domain-wide delegation."""
    credentials_file = get_docker_or_local_path(
        docker_path=SERVICE_ACCOUNT_FILE,
        config_path=config_path
    )
    credentials = service_account.Credentials.from_service_account_file(
        credentials_file, scopes=SCOPES)
    delegated_credentials = credentials.with_subject(delegated_user)
    return delegated_credentials

def get_oauth_credentials(credentials_file: str) -> Credentials:
    """
    Get OAuth 2.0 credentials from token JSON file.

    Args:
        credentials_file: Path to the OAuth token JSON file

    Returns:
        OAuth credentials object
    """
    try:
        # Read the token file
        with open(credentials_file, 'r') as f:
            token_data = json.load(f)

        # Create credentials from the token data
        creds = Credentials.from_authorized_user_info(token_data, SCOPES)

        # Refresh if expired
        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                logger.info("Refreshed OAuth token")

                # Save the refreshed token back to the file
                refreshed_token_data = {
                    "token": creds.token,
                    "refresh_token": creds.refresh_token,
                    "token_uri": creds.token_uri,
                    "client_id": creds.client_id,
                    "client_secret": creds.client_secret,
                    "scopes": creds.scopes
                }
                with open(credentials_file, 'w') as f:
                    json.dump(refreshed_token_data, f, indent=2)
                logger.info(f"Saved refreshed token to {credentials_file}")
            except Exception as e:
                logger.error(f"Error refreshing token: {e}")
                raise

        return creds
    except FileNotFoundError:
        logger.error(f"OAuth credentials file not found: {credentials_file}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid OAuth token JSON in {credentials_file}: {e}")
        raise ValueError(f"Invalid OAuth token format in credentials file: {e}")
    except Exception as e:
        logger.error(f"Error creating OAuth credentials: {e}")
        raise

def get_gdrive_url(file_id: str, mime_type: str = '') -> str:
    if mime_type == 'application/vnd.google-apps.document':
        url = f'https://docs.google.com/document/d/{file_id}/view'
    elif mime_type == 'application/vnd.google-apps.spreadsheet':
        url = f'https://docs.google.com/spreadsheets/d/{file_id}/view'
    elif mime_type == 'application/vnd.google-apps.presentation':
        url = f'https://docs.google.com/presentation/d/{file_id}/view'
    else:
        url = f'https://drive.google.com/file/d/{file_id}/view'
    return url

# List of permission display names that are allowed to be crawled
# In this example only files shared with 'Vectara' or 'all' are allowed
# this means that only files shared with anyone in Vectara or files shared with anyone (public) are included
DEFAULT_PERMISSIONS = ['Vectara', 'all']

class UserWorker(object):
    def __init__(
            self,
            cfg: dict,
            indexer: Indexer, crawler: Crawler,
            shared_cache: SharedCache,
            date_threshold: datetime,
            permissions: List = DEFAULT_PERMISSIONS,
            use_ray: bool = False) -> None:
        # Convert cfg back to OmegaConf if it's a dict (from Ray serialization)
        if isinstance(cfg, dict):
            self.cfg = OmegaConf.create(cfg)
        else:
            self.cfg = cfg
        self.crawler = crawler
        self.indexer = indexer
        self.creds = None
        self.service = None
        self.access_token = None
        self.shared_cache = shared_cache
        self.date_threshold = date_threshold
        self.permissions = permissions
        self.use_ray = use_ray
        # Get folder_ids from config
        self.folder_ids = self.cfg.gdrive_crawler.get("folder_ids", [])
        logger.info(f"UserWorker initialized with folder_ids: {self.folder_ids}, permissions: {self.permissions}, days_back threshold: {date_threshold}")

    def setup(self):
        self.indexer.setup(use_playwright=False)
        setup_logging()

    def list_files_in_folder(self, service: Resource, folder_id: str, date_threshold: Optional[str] = None) -> List[dict]:
        """List all files recursively in a specific folder."""
        results = []
        page_token = None
        # Query for files in the specific folder
        query = f"('{folder_id}' in parents) and trashed=false and modifiedTime > '{date_threshold}'"
        
        logger.info(f"Searching for files in folder_id: {folder_id} with query: {query}")
        
        while True:
            try:
                params = {
                    'fields': 'nextPageToken, files(id, name, mimeType, permissions, modifiedTime, createdTime, owners, size, parents)',
                    'q': query,
                    'corpora': 'allDrives',
                    'includeItemsFromAllDrives': True,
                    'supportsAllDrives': True
                }
                if page_token:
                    params['pageToken'] = page_token
                response = service.files().list(**params).execute()
                files = response.get('files', [])
                logger.info(f"Found {len(files)} items in folder {folder_id} (page)")

                for file in files:
                    file_id = file.get('id')
                    mime_type = file.get('mimeType', '')
                    name = file.get('name', 'Unknown')
                    
                    # If it's a folder, recursively list files in it
                    if mime_type == 'application/vnd.google-apps.folder':
                        logger.info(f"Found subfolder: {name} (id: {file_id}), recursing into it")
                        subfolder_files = self.list_files_in_folder(service, file_id, date_threshold)
                        results.extend(subfolder_files)
                    else:
                        # It's a file, check permissions
                        # Note: permissions might not be populated in the list response
                        permissions = file.get('permissions', [])
                        permission_names = [p.get('displayName', '') for p in permissions] if permissions else []
                        
                        # Check authentication type - for OAuth, if we can list the file, we can access it
                        auth_type = self.cfg.gdrive_crawler.get("auth_type", "service_account")
                        
                        logger.info(f"File: {name} (id: {file_id}), mime: {mime_type}, permissions in response: {len(permissions)} items")
                        if permissions:
                            logger.info(f"  Permission details: {[{'displayName': p.get('displayName'), 'type': p.get('type'), 'role': p.get('role')} for p in permissions]}")
                        
                        # For OAuth, skip permission check - if file is listed, user has access
                        if auth_type == "oauth":
                            logger.info(f"  OAuth mode: adding file {name} (id: {file_id}) - access granted by folder access")
                            results.append(file)
                        # For service account, check permissions
                        elif not permissions:
                            logger.info(f"  No permissions in list response for {name}, assuming accessible (likely owned by user)")
                            results.append(file)
                            logger.info(f"  Added file: {name} (id: {file_id})")
                        elif any(p.get('displayName') in self.permissions for p in permissions):
                            results.append(file)
                            logger.info(f"  Added file: {name} (id: {file_id}) - permission match")
                        else:
                            logger.warning(f"  Skipped file {name} (id: {file_id}) - permission check failed. Permissions: {permission_names}, required: {self.permissions}")
                
                page_token = response.get('nextPageToken', None)
                if not page_token:
                    break
            except Exception as error:
                logger.error(f"An HTTP error occurred while listing folder {folder_id}: {error}")
                break
        
        logger.info(f"Total files found in folder {folder_id} (including subfolders): {len(results)}")
        return results

    def list_files(self, service: Resource, date_threshold: Optional[str] = None) -> List[dict]:
        """List files based on folder_ids config or default query."""
        results = []
        
        # If folder_ids are specified, use them
        if self.folder_ids:
            logger.info(f"Using folder_ids from config: {self.folder_ids}")
            for folder_id in self.folder_ids:
                logger.info(f"Processing folder_id: {folder_id}")
                try:
                    # Verify folder exists and get its name
                    folder_meta = service.files().get(fileId=folder_id, fields='id, name, mimeType').execute()
                    folder_name = folder_meta.get('name', 'Unknown')
                    folder_mime = folder_meta.get('mimeType', '')
                    logger.info(f"Folder details - Name: {folder_name}, ID: {folder_id}, MIME: {folder_mime}")
                    
                    if folder_mime != 'application/vnd.google-apps.folder':
                        logger.warning(f"ID {folder_id} is not a folder (MIME type: {folder_mime}), skipping")
                        continue
                    
                    folder_files = self.list_files_in_folder(service, folder_id, date_threshold)
                    logger.info(f"Found {len(folder_files)} files in folder '{folder_name}' (id: {folder_id})")
                    results.extend(folder_files)
                except HttpError as e:
                    logger.error(f"Error accessing folder {folder_id}: {e.resp.status} - {e.error_details}")
                except Exception as e:
                    logger.error(f"Unexpected error processing folder {folder_id}: {e}")
        else:
            # Default behavior: search root, shared files, etc.
            logger.info("No folder_ids specified, using default query (root, sharedWithMe, etc.)")
            page_token = None
            query = f"((('root' in parents) or sharedWithMe or ('me' in owners) or ('me' in writers) or ('me' in readers)) and trashed=false and modifiedTime > '{date_threshold}')"
            logger.info(f"Using query: {query}")

            while True:
                try:
                    params = {
                        'fields': 'nextPageToken, files(id, name, mimeType, permissions, modifiedTime, createdTime, owners, size)',
                        'q': query,
                        'corpora': 'allDrives',
                        'includeItemsFromAllDrives': True,
                        'supportsAllDrives': True
                    }
                    if page_token:
                        params['pageToken'] = page_token
                    response = service.files().list(**params).execute()
                    files = response.get('files', [])
                    logger.info(f"Found {len(files)} files in default query (page)")

                    for file in files:
                        permissions = file.get('permissions', [])
                        permission_names = [p.get('displayName', '') for p in permissions]
                        file_name = file.get('name', 'Unknown')
                        logger.debug(f"File: {file_name}, permissions: {permission_names}")
                        
                        if any(p.get('displayName') in self.permissions for p in permissions):
                            results.append(file)
                            logger.debug(f"Added file: {file_name}")
                        else:
                            logger.debug(f"Skipped file {file_name} - permission check failed")
                            
                    page_token = response.get('nextPageToken', None)
                    if not page_token:
                        break
                except Exception as error:
                    logger.error(f"An HTTP error occurred: {error}")
                    break
        
        logger.info(f"Total files found (after all processing): {len(results)}")
        return results

    def download_or_export_file(self, file_id: str, mime_type: Optional[str] = None) -> Optional[io.BytesIO]:
        logger.debug(f"download_or_export_file called for file_id: {file_id}, export mime_type: {mime_type}")
        try:
            if mime_type:
                logger.debug(f"Exporting file {file_id} as {mime_type}")
                request = self.service.files().export_media(fileId=file_id, mimeType=mime_type)
            else:
                logger.debug(f"Downloading file {file_id} directly")
                request = self.service.files().get_media(fileId=file_id)

            byte_stream = io.BytesIO()
            downloader = MediaIoBaseDownload(byte_stream, request)
            done = False
            chunk_count = 0
            while not done:
                status, done = downloader.next_chunk()
                chunk_count += 1
                if status:
                    logger.debug(f"Download progress: {int(status.progress() * 100)}%")
            byte_stream.seek(0)
            file_size = len(byte_stream.read())
            byte_stream.seek(0)  # Reset after reading size
            logger.debug(f"Successfully downloaded {file_size} bytes in {chunk_count} chunks")
            return byte_stream

        except HttpError as error:
            logger.warning(f"HttpError downloading file {file_id}: status={error.resp.status}, details={error.error_details}")
            if error.resp.status == 403 and \
               any(e.get('reason') == 'exportSizeLimitExceeded' or e.get('reason') == 'fileNotDownloadable' for e in error.error_details):
                logger.info(f"Trying alternative download method for file {file_id} via exportLinks")
                get_url = f'https://www.googleapis.com/drive/v3/files/{file_id}?fields=exportLinks'
                headers = {
                    'Authorization': f'Bearer {self.access_token}',
                    'Accept': 'application/json',
                }
                response = requests.get(get_url, headers=headers)
                if response.status_code == 200:
                    export_links = response.json().get('exportLinks', {})
                    logger.debug(f"Available export links: {list(export_links.keys())}")
                    pdf_link = export_links.get('application/pdf')
                    if pdf_link:
                        logger.info(f"Downloading file {file_id} via PDF export link")
                        pdf_response = requests.get(pdf_link, headers=headers)
                        if pdf_response.status_code == 200:
                            logger.info(f"Downloaded file {file_id} via link (as pdf)")
                            return io.BytesIO(pdf_response.content)
                        else:
                            logger.error(f"An error occurred loading via link: {pdf_response.status_code}")
                    else:
                        logger.warning(f"No PDF export link available for file {file_id}")
                else:
                    logger.error(f"Failed to get export links: {response.status_code}")
            else:
                logger.error(f"An error occurred downloading file {file_id}: {error}")

            return None
        except Exception as e:
            logger.error(f"Unexpected error downloading file {file_id}: {e}", exc_info=True)
            return None

    def save_local_file(self, file_id: str, name: str, mime_type: Optional[str] = None) -> Optional[str]:
        path, extension = os.path.splitext(name)
        sanitized_name = f"{slugify(path)}{extension}"
        file_path = os.path.join("/tmp", sanitized_name)
        logger.debug(f"Saving file {name} (id: {file_id}) to {file_path}, export mime: {mime_type}")
        try:
            byte_stream = self.download_or_export_file(file_id, mime_type)
            if byte_stream:
                file_size = len(byte_stream.read())
                byte_stream.seek(0)  # Reset to beginning after reading size
                logger.debug(f"Downloaded {file_size} bytes for file {name}")
                with open(file_path, 'wb') as f:
                    f.write(byte_stream.read())
                logger.debug(f"Saved file to {file_path}")
                return file_path
            else:
                logger.warning(f"download_or_export_file returned None for {name} (id: {file_id})")
        except Exception as e:
            logger.error(f"Error saving local file {name} (id: {file_id}): {e}", exc_info=True)
        return None

    def crawl_file(self, file: dict) -> None:
        file_id = file['id']
        mime_type = file['mimeType']
        name = file['name']
        permissions = file.get('permissions', [])
        permission_names = [p.get('displayName', '') for p in permissions]

        logger.info(f"Crawling file: {name} (id: {file_id}, mime: {mime_type}, permissions: {permission_names})")

        # Check authentication type - for OAuth, if we can list the file, we can access it
        auth_type = self.cfg.gdrive_crawler.get("auth_type", "service_account")
        
        if auth_type == "oauth":
            # For OAuth, skip permission check - if file is listed, user has access
            logger.debug(f"OAuth mode: skipping permission check for {name}")
        else:
            # For service account, check permissions
            if not any(p.get('displayName') == 'Vectara' or p.get('displayName') == 'all' for p in permissions):
                logger.info(f"Skipping restricted file: {name} (permissions: {permission_names})")
                return None

        url = get_gdrive_url(file_id, mime_type)
        logger.debug(f"Generated URL for file {name}: {url}")
        
        if mime_type == 'application/vnd.google-apps.document':
            logger.debug(f"Exporting Google Doc {name} as DOCX")
            local_file_path = self.save_local_file(file_id, name + '.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')
        elif mime_type == 'application/vnd.google-apps.presentation':
            logger.debug(f"Exporting Google Slides {name} as PPTX")
            local_file_path = self.save_local_file(file_id, name + '.pptx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation')
        elif mime_type == 'application/vnd.google-apps.spreadsheet':
            logger.debug(f"Exporting Google Sheet {name} as XLSX")
            local_file_path = self.save_local_file(file_id, name + '.xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        elif mime_type == 'application/pdf':
            logger.info(f"Downloading PDF file: {name}")
            local_file_path = self.save_local_file(file_id, name)
        else:
            logger.debug(f"Downloading file {name} directly (MIME: {mime_type})")
            local_file_path = self.save_local_file(file_id, name)

        if not local_file_path:
            logger.warning(f"Failed to download/export file: {name} (id: {file_id}, mime: {mime_type})")
            return

        supported_extensions = ['.doc', '.docx', '.ppt', '.pptx', '.pdf', '.odt', '.txt', '.html', '.md', '.rtf', '.epub', '.lxml', '.xlsx', '.xls']
        if not any(local_file_path.endswith(extension) for extension in supported_extensions):
            logger.info(f"Skipping unsupported file type: {name} (path: {local_file_path})")
            safe_remove_file(local_file_path)
            return

        logger.info(f"Successfully downloaded file: {name} to {local_file_path}")

        if self.crawler.verbose:
            logger.info(f"Handling file: '{name}' with MIME type '{mime_type}'")

        created_time = file.get('createdTime', 'N/A')
        modified_time = file.get('modifiedTime', 'N/A')
        owners = ', '.join([owner['displayName'] for owner in file.get('owners', [])])
        size = file.get('size', 'N/A')

        logger.info(f'Indexing file: {name} (size: {size}, created: {created_time}, modified: {modified_time}, owners: {owners})')
        file_metadata = {
            'id': file_id,
            'name': name,
            'title': name,
            'created_at': created_time,
            'last_updated': modified_time,
            'owners': owners,
            'size': size,
            'url': get_gdrive_url(file_id, mime_type),
            'source': 'gdrive'
        }

        try:
            logger.debug(f"Calling indexer.index_file for {name}")
            result = self.indexer.index_file(filename=local_file_path, uri=url, metadata=file_metadata)
            if result:
                logger.info(f"✓ Successfully indexed file: {name} to Vectara corpus")
            else:
                logger.error(f"✗ Failed to index file: {name} - check previous error messages")
        except Exception as e:
            logger.error(f"Error indexing document for file {name}, file_id {file_id}: {e}", exc_info=True)

        # remove file from local storage
        safe_remove_file(local_file_path)
        logger.debug(f"Removed temporary file: {local_file_path}")

    def process(self, user: str) -> None:
        logger.info(f"Processing files for user: {user}")
        logger.info(f"Date threshold: {self.date_threshold.isoformat()}")
        logger.info(f"Folder IDs to process: {self.folder_ids}")
        logger.info(f"Permission filters: {self.permissions}")

        # Determine authentication method based on configuration
        auth_type = self.cfg.gdrive_crawler.get("auth_type", "service_account")
        logger.info(f"Authentication type: {auth_type}")

        # Get credentials file path (same field name for both auth types)
        credentials_file = get_docker_or_local_path(
            docker_path=SERVICE_ACCOUNT_FILE,
            config_path=self.cfg.gdrive_crawler.credentials_file
        )
        logger.info(f"Using credentials file: {credentials_file}")

        if auth_type == "oauth":
            # Use OAuth authentication with token from credentials.json
            logger.info("Using OAuth authentication")
            self.creds = get_oauth_credentials(credentials_file)
        else:
            # Use service account with domain-wide delegation (default)
            logger.info(f"Using service account authentication for user: {user}")
            self.creds = get_credentials(user, config_path=self.cfg.gdrive_crawler.credentials_file)

        logger.info("Building Google Drive service...")
        self.service = build("drive", "v3", credentials=self.creds, cache_discovery=False)
        logger.info("Google Drive service built successfully")

        logger.info(f"Listing files with date threshold: {self.date_threshold.isoformat()}Z")
        files = self.list_files(self.service, date_threshold=self.date_threshold.isoformat() + 'Z')
        logger.info(f"Initial file list returned {len(files)} files")
        
        # Filter out already processed files
        initial_count = len(files)
        if self.use_ray:
            files = [file for file in files if not ray.get(self.shared_cache.contains.remote(file['id']))]
        else:
            files = [file for file in files if not self.shared_cache.contains(file['id'])]
        logger.info(f"After cache filtering: {len(files)} files (removed {initial_count - len(files)} already processed)")

        # remove mime types we don't want to crawl
        mime_prefix_to_remove = [
            'image', 'audio', 'video',
            'application/vnd.google-apps.folder', 'application/x-adobe-indesign',
            'application/x-rar-compressed', 'application/zip', 'application/x-7z-compressed',
            'application/x-executable',
            'text/php', 'text/javascript', 'text/css', 'text/xml', 'text/x-sql', 'text/x-python-script',
        ]
        before_mime_filter = len(files)
        files = [file for file in files if not any(file['mimeType'].startswith(mime_type) for mime_type in mime_prefix_to_remove)]
        logger.info(f"After MIME type filtering: {len(files)} files (removed {before_mime_filter - len(files)} unsupported types)")
        
        # Log file types found
        mime_types = {}
        for file in files:
            mime = file.get('mimeType', 'unknown')
            mime_types[mime] = mime_types.get(mime, 0) + 1
        logger.info(f"File types found: {mime_types}")

        if self.crawler.verbose:
            logging.info(f"identified {len(files)} files for user {user}")

        # get access token
        try:
            logger.info("Refreshing credentials to get access token...")
            self.creds.refresh(Request())
            self.access_token = self.creds.token
            logger.info("Access token obtained successfully")
        except Exception as e:
            logger.error(f"Error refreshing token: {e} for user {user}")
            return

        logger.info(f"Starting to process {len(files)} files...")
        processed_count = 0
        skipped_count = 0
        error_count = 0
        
        for idx, file in enumerate(files, 1):
            file_id = file.get('id')
            file_name = file.get('name', 'Unknown')
            logger.info(f"[{idx}/{len(files)}] Processing file: {file_name} (id: {file_id})")
            
            if self.use_ray:
                if not ray.get(self.shared_cache.contains.remote(file_id)):
                    self.shared_cache.add.remote(file_id)
            else:
                if not self.shared_cache.contains(file_id):
                    self.shared_cache.add(file_id)
            
            try:
                self.crawl_file(file)
                processed_count += 1
            except Exception as e:
                logger.error(f"Error processing file {file_name} (id: {file_id}): {e}")
                error_count += 1
        
        logger.info(f"Processing complete. Processed: {processed_count}, Skipped: {skipped_count}, Errors: {error_count}")

class GdriveCrawler(Crawler):

    def __init__(self, cfg: OmegaConf, endpoint: str, corpus_key: str, api_key: str) -> None:
        super().__init__(cfg, endpoint, corpus_key, api_key)
        logger.info("Google Drive Crawler initialized")

        # Get auth type
        auth_type = cfg.gdrive_crawler.get("auth_type", "service_account")

        # For OAuth mode, use a dummy user; for service account, use delegated_users
        if auth_type == "oauth":
            self.delegated_users = ["oauth_user"]  # Dummy user for OAuth mode
        else:
            self.delegated_users = cfg.gdrive_crawler.delegated_users

    def crawl(self) -> None:
        N = self.cfg.gdrive_crawler.get("days_back", 7)
        date_threshold = datetime.now() - timedelta(days=N)
        folder_ids = self.cfg.gdrive_crawler.get("folder_ids", [])
        
        logger.info("=" * 80)
        logger.info("Starting Google Drive crawl")
        logger.info(f"Days back: {N}")
        logger.info(f"Date threshold: {date_threshold.isoformat()}")
        logger.info(f"Folder IDs: {folder_ids}")
        logger.info(f"Delegated users: {self.delegated_users}")
        logger.info("=" * 80)
        
        if self.verbose:
            logger.info(f"Crawling documents from {date_threshold.date()}")
        ray_workers = self.cfg.gdrive_crawler.get("ray_workers", 0)            # -1: use ray with ALL cores, 0: dont use ray
        permissions = self.cfg.gdrive_crawler.get("permissions", ['Vectara', 'all'])
        logger.info(f"Ray workers: {ray_workers}, Permissions filter: {permissions}")

        if ray_workers > 0:
            logger.info(f"Using {ray_workers} ray workers")
            self.indexer.p = self.indexer.browser = None
            ray.init(num_cpus=ray_workers, log_to_driver=True, include_dashboard=False)
            shared_cache = ray.remote(SharedCache).remote()
            # Convert OmegaConf to dict for proper Ray serialization
            cfg_dict = OmegaConf.to_container(self.cfg, resolve=True)
            actors = [ray.remote(UserWorker).remote(cfg_dict, self.indexer, self, shared_cache, date_threshold, permissions, use_ray=True) for _ in range(ray_workers)]
            for a in actors:
                a.setup.remote()
            pool = ray.util.ActorPool(actors)
            _ = list(pool.map(lambda a, user: a.process.remote(user), self.delegated_users))
            ray.shutdown()

        else:
            shared_cache = SharedCache()
            crawl_worker = UserWorker(self.cfg, self.indexer, self, shared_cache, date_threshold, permissions, use_ray=False)
            for user in self.delegated_users:
                logger.info(f"Crawling for user {user}")
                crawl_worker.process(user)
        
        logger.info("=" * 80)
        logger.info("Google Drive crawl completed")
        logger.info("=" * 80)
