#!/usr/bin/env python3
"""
ACI to FireMon Configuration Transfer Script

This script retrieves configuration data from a Cisco ACI device and posts it to
a FireMon revision. It's designed to run on a FireMon virtual appliance.

Features:
- Authenticates with Cisco ACI and retrieves configuration data
- Authenticates with FireMon API
- Gets the latest revision ID for the device
- Posts the configuration files to FireMon

Authentication Options:
1. Command-line arguments (most secure, recommended for automation)
2. Environment variables
3. Interactive prompts (if credentials aren't provided via flags or environment)
4. Hard-coded credentials in the script (least secure, use only for testing)

Usage:
    python3 aci_firemon_script.py [options]

Options:
    --aci-host          Cisco ACI hostname or IP
    --aci-username      Cisco ACI username
    --aci-password      Cisco ACI password
    --firemon-host      FireMon hostname or IP
    --firemon-username  FireMon username
    --firemon-password  FireMon password
    --domain-id         FireMon domain ID
    --device-id         FireMon device ID
    --no-prompt         Don't prompt for missing credentials
    --help              Show this help message and exit

Environment Variables:
    ACI_HOST            Cisco ACI hostname or IP
    ACI_USERNAME        Cisco ACI username
    ACI_PASSWORD        Cisco ACI password
    FIREMON_HOST        FireMon hostname or IP
    FIREMON_USERNAME    FireMon username
    FIREMON_PASSWORD    FireMon password
    FIREMON_DOMAIN_ID   FireMon domain ID
    FIREMON_DEVICE_ID   FireMon device ID

Example:
    python3 aci_firemon_script.py --aci-host 192.168.101.4 --aci-username admin \\
        --firemon-host adam.lab.firemon.com --domain-id 1 --device-id 8

Notes:
    - If credentials are not provided via command-line arguments or environment
      variables, the script will prompt for them (unless --no-prompt is specified).
    - Domain ID and device ID must be provided via command-line arguments or
      environment variables; they will not be prompted for.
"""

# Ensure required packages are available
import sys
import os
import importlib

def ensure_module(module_name):
    """
    Dynamically import a module by searching for it in potential site-packages locations.
    
    Args:
        module_name (str): Name of the module to import
        
    Returns:
        module: The imported module
        
    Raises:
        ImportError: If the module cannot be found
    """
    # First try the normal import in case it's already in the path
    try:
        return importlib.import_module(module_name)
    except ImportError:
        pass
    
    # Get the current Python version
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    
    # Create a list of potential paths to check
    base_path = '/usr/lib/firemon/devpackfw/lib'
    potential_paths = [
        # Current Python version
        f"{base_path}/python{py_version}/site-packages",
        # Exact Python version with patch
        f"{base_path}/python{sys.version.split()[0]}/site-packages",
        # Try a range of nearby versions (for future-proofing)
        *[f"{base_path}/python3.{i}/site-packages" for i in range(8, 20)]
    ]
    
    # Try each path
    for path in potential_paths:
        if os.path.exists(path):
            if path not in sys.path:
                sys.path.append(path)
                print(f"Added potential module path: {path}")
            try:
                return importlib.import_module(module_name)
            except ImportError:
                continue
    
    # If we get here, we couldn't find the module
    raise ImportError(f"Could not find module {module_name} in any potential site-packages location")

# Import required modules
try:
    requests = ensure_module("requests")
except ImportError:
    print("ERROR: Required package 'requests' not found in any potential location.")
    print("Please install it using: pip install requests")
    sys.exit(1)

import json
import argparse
import getpass
import tempfile
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Add warning about SSL verification
print("WARNING: SSL certificate verification is disabled for both ACI and FireMon API calls.")
print("         This is insecure and should only be used in testing environments.")

# HARD-CODED CREDENTIALS (USE WITH CAUTION - UNCOMMENT AND MODIFY IF NEEDED)
# ---------------------------------
# HARD_CODED_ACI_HOST = "192.168.101.4"
# HARD_CODED_ACI_USERNAME = "seadmin"
# HARD_CODED_ACI_PASSWORD = "S3cur3P!"
# HARD_CODED_FIREMON_HOST = "adam.lab.firemon.com"
# HARD_CODED_FIREMON_USERNAME = "firemon"
# HARD_CODED_FIREMON_PASSWORD = "firemon"
# HARD_CODED_DOMAIN_ID = 1
# HARD_CODED_DEVICE_ID = 8


def authenticate_aci(aci_host, username, password):
    """
    Authenticate with Cisco ACI and return cookie.
    
    Args:
        aci_host (str): Hostname or IP address of the ACI device
        username (str): ACI username
        password (str): ACI password
        
    Returns:
        requests.cookies.RequestsCookieJar: Session cookies
        
    Raises:
        requests.exceptions.RequestException: If authentication fails
    """
    auth_url = f"https://{aci_host}/api/aaaLogin.json"
    auth_payload = {
        "aaaUser": {
            "attributes": {
                "name": username,
                "pwd": password
            }
        }
    }
    
    try:
        response = requests.post(auth_url, json=auth_payload, verify=False, timeout=30)
        response.raise_for_status()
        return response.cookies
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to authenticate with ACI: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            if e.response.status_code == 401:
                print("Authentication failed: Invalid username or password")
            print(f"Response: {e.response.text}")
        raise


def get_aci_data(aci_host, cookies):
    """
    Get configuration data from Cisco ACI.
    
    Args:
        aci_host (str): Hostname or IP address of the ACI device
        cookies (requests.cookies.RequestsCookieJar): Session cookies
        
    Returns:
        dict: Configuration data from various ACI endpoints
        
    Raises:
        requests.exceptions.RequestException: If data retrieval fails
    """
    endpoints = {
        "ntp_providers": "api/class/datetimeNtpProvider.json",
        "syslog_remote_dest": "api/class/syslogRemoteDest.json",
        "pki_web_token": "api/class/pkiWebTokenData.json",
        "aaa_default_auth": "api/class/aaaDefaultAuth.json"
    }
    
    data = {}
    
    for name, endpoint in endpoints.items():
        url = f"https://{aci_host}/{endpoint}"
        print(f"Retrieving {name} from {url}")
        try:
            response = requests.get(url, cookies=cookies, verify=False, timeout=30)
            response.raise_for_status()
            data[name] = response.text
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Failed to retrieve {name}: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response: {e.response.text}")
            raise
        
    return data


def authenticate_firemon(firemon_host, username, password):
    """
    Authenticate with FireMon API and return an authenticated session.
    
    Args:
        firemon_host (str): Hostname or IP address of the FireMon server
        username (str): FireMon username
        password (str): FireMon password
        
    Returns:
        requests.Session: Authenticated session object
        
    Raises:
        requests.exceptions.RequestException: If authentication fails
        ValueError: If authentication status is not AUTHORIZED
    """
    # Initialize session
    session = requests.Session()
    session.verify = False  # Disable SSL verification
    session.auth = (username, password)  # Set basic auth
    session.headers.update({
        'Content-Type': 'application/json',
        'accept': 'application/json'
    })
    
    # Prepare authentication payload
    auth_payload = {
        "username": username,
        "password": password
    }
    
    try:
        # Use the validate endpoint as shown in the example script
        auth_url = f"https://{firemon_host}/securitymanager/api/authentication/validate"
        response = session.post(auth_url, data=json.dumps(auth_payload), timeout=30)
        response.raise_for_status()
        
        auth_data = response.json()
        auth_status = auth_data.get('authStatus', '')
        
        if auth_status != 'AUTHORIZED':
            raise ValueError(f"Authentication failed with status: {auth_status}")
        
        # Now try to authenticate with the login endpoint to get a token
        login_url = f"https://{firemon_host}/securitymanager/api/authentication/login"
        login_response = session.post(login_url, data=json.dumps(auth_payload), timeout=30)
        login_response.raise_for_status()
        
        login_data = login_response.json()
        if 'token' in login_data:
            # Add token to session headers
            session.headers.update({'SESSIONID': login_data['token']})
            print(f"Successfully obtained authentication token")
        
        print(f"Authentication successful with status: {auth_status}")
        return session
    except (requests.exceptions.RequestException, ValueError) as e:
        print(f"ERROR: Failed to authenticate with FireMon: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            if e.response.status_code == 401:
                print("Authentication failed: Invalid username or password")
            print(f"Response: {e.response.text}")
        raise


def get_latest_revision(firemon_host, session, domain_id, device_id):
    """
    Get the latest revision ID for a device.
    
    Args:
        firemon_host (str): Hostname or IP address of the FireMon server
        session (requests.Session): Authenticated session
        domain_id (int): FireMon domain ID
        device_id (int): FireMon device ID
        
    Returns:
        int: Revision ID
        
    Raises:
        requests.exceptions.RequestException: If retrieval fails
        ValueError: If no revision ID is found
    """
    url = f"https://{firemon_host}/securitymanager/api/domain/{domain_id}/device/{device_id}/rev/latest"
    
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        
        revision_data = response.json()
        if "id" not in revision_data:
            raise ValueError("No revision ID in response from FireMon")
        return revision_data["id"]
    except (requests.exceptions.RequestException, ValueError) as e:
        print(f"ERROR: Failed to get latest revision ID: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")
        raise


def post_files_to_firemon(firemon_host, session, revision_id, aci_data):
    """
    Post configuration files to FireMon API.
    
    Args:
        firemon_host (str): Hostname or IP address of the FireMon server
        session (requests.Session): Authenticated session
        revision_id (int): Revision ID
        aci_data (dict): Configuration data
        
    Returns:
        dict: Response from FireMon API
        
    Raises:
        requests.exceptions.RequestException: If post fails
    """
    url = f"https://{firemon_host}/securitymanager/api/rev/{revision_id}/nd/file?filetype=CONFIG"
    
    # Temporarily remove Content-Type header for multipart upload
    content_type = session.headers.pop('Content-Type', None)
    
    # Create temporary files
    temp_files = []
    
    try:
        # Create the temporary files
        for name, content in aci_data.items():
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_file.write(content.encode('utf-8'))
            temp_file.close()
            temp_files.append((name, temp_file.name))
        
        # Create multipart form data
        files = []
        for name, file_path in temp_files:
            # Add file in the correct format: 'filename=@file_path'
            files.append(('filename', (name, open(file_path, 'rb'))))
        
        # Make the request (let requests handle the multipart content type)
        response = session.post(url, files=files, timeout=60)
        response.raise_for_status()
        
        # Restore the Content-Type header
        if content_type:
            session.headers['Content-Type'] = content_type
            
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to post files to FireMon: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response: {e.response.text}")
        raise
    finally:
        # Restore the Content-Type header if not already done
        if content_type and 'Content-Type' not in session.headers:
            session.headers['Content-Type'] = content_type
            
        # Close and delete temporary files
        for name, file_path in temp_files:
            try:
                # Close any open file handles
                os.unlink(file_path)
            except:
                pass


def parse_arguments():
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description='Upload ACI configuration files to FireMon',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument('--aci-host', help='Cisco ACI hostname or IP')
    parser.add_argument('--aci-username', help='Cisco ACI username')
    parser.add_argument('--aci-password', help='Cisco ACI password')
    parser.add_argument('--firemon-host', help='FireMon hostname or IP')
    parser.add_argument('--firemon-username', help='FireMon username')
    parser.add_argument('--firemon-password', help='FireMon password')
    parser.add_argument('--domain-id', type=int, help='FireMon domain ID')
    parser.add_argument('--device-id', type=int, help='FireMon device ID')
    parser.add_argument('--no-prompt', action='store_true', help="Don't prompt for missing credentials")
    
    return parser.parse_args()


def get_credentials(args):
    """
    Get credentials from various sources: command-line arguments, environment variables,
    hard-coded values (if uncommented), or prompt the user.
    
    Args:
        args (argparse.Namespace): Command-line arguments
        
    Returns:
        tuple: (aci_host, aci_username, aci_password, firemon_host, firemon_username, 
               firemon_password, domain_id, device_id)
               
    Raises:
        ValueError: If required credentials are missing
    """
    # Start with command-line arguments
    aci_host = args.aci_host
    aci_username = args.aci_username
    aci_password = args.aci_password
    firemon_host = args.firemon_host
    firemon_username = args.firemon_username
    firemon_password = args.firemon_password
    domain_id = args.domain_id
    device_id = args.device_id
    
    # Try environment variables for any missing values
    if aci_host is None:
        aci_host = os.environ.get('ACI_HOST')
    if aci_username is None:
        aci_username = os.environ.get('ACI_USERNAME')
    if aci_password is None:
        aci_password = os.environ.get('ACI_PASSWORD')
    if firemon_host is None:
        firemon_host = os.environ.get('FIREMON_HOST')
    if firemon_username is None:
        firemon_username = os.environ.get('FIREMON_USERNAME')
    if firemon_password is None:
        firemon_password = os.environ.get('FIREMON_PASSWORD')
    if domain_id is None:
        domain_id_str = os.environ.get('FIREMON_DOMAIN_ID')
        if domain_id_str:
            try:
                domain_id = int(domain_id_str)
            except ValueError:
                print(f"WARNING: Invalid FIREMON_DOMAIN_ID: {domain_id_str}")
    if device_id is None:
        device_id_str = os.environ.get('FIREMON_DEVICE_ID')
        if device_id_str:
            try:
                device_id = int(device_id_str)
            except ValueError:
                print(f"WARNING: Invalid FIREMON_DEVICE_ID: {device_id_str}")
    
    # Try hard-coded values for any missing values (if they're defined)
    if 'HARD_CODED_ACI_HOST' in globals() and aci_host is None:
        aci_host = globals()['HARD_CODED_ACI_HOST']
    if 'HARD_CODED_ACI_USERNAME' in globals() and aci_username is None:
        aci_username = globals()['HARD_CODED_ACI_USERNAME']
    if 'HARD_CODED_ACI_PASSWORD' in globals() and aci_password is None:
        aci_password = globals()['HARD_CODED_ACI_PASSWORD']
    if 'HARD_CODED_FIREMON_HOST' in globals() and firemon_host is None:
        firemon_host = globals()['HARD_CODED_FIREMON_HOST']
    if 'HARD_CODED_FIREMON_USERNAME' in globals() and firemon_username is None:
        firemon_username = globals()['HARD_CODED_FIREMON_USERNAME']
    if 'HARD_CODED_FIREMON_PASSWORD' in globals() and firemon_password is None:
        firemon_password = globals()['HARD_CODED_FIREMON_PASSWORD']
    if 'HARD_CODED_DOMAIN_ID' in globals() and domain_id is None:
        domain_id = globals()['HARD_CODED_DOMAIN_ID']
    if 'HARD_CODED_DEVICE_ID' in globals() and device_id is None:
        device_id = globals()['HARD_CODED_DEVICE_ID']
    
    # Prompt for any missing values, if allowed
    if not args.no_prompt:
        if aci_host is None:
            aci_host = input("Enter Cisco ACI hostname or IP: ")
        if aci_username is None:
            aci_username = input("Enter Cisco ACI username: ")
        if aci_password is None:
            aci_password = getpass.getpass("Enter Cisco ACI password: ")
        if firemon_host is None:
            firemon_host = input("Enter FireMon hostname or IP: ")
        if firemon_username is None:
            firemon_username = input("Enter FireMon username: ")
        if firemon_password is None:
            firemon_password = getpass.getpass("Enter FireMon password: ")
    
    # Check for required values
    missing = []
    if aci_host is None:
        missing.append("ACI hostname/IP")
    if aci_username is None:
        missing.append("ACI username")
    if aci_password is None:
        missing.append("ACI password")
    if firemon_host is None:
        missing.append("FireMon hostname/IP")
    if firemon_username is None:
        missing.append("FireMon username")
    if firemon_password is None:
        missing.append("FireMon password")
    if domain_id is None:
        missing.append("FireMon domain ID")
    if device_id is None:
        missing.append("FireMon device ID")
    
    if missing:
        raise ValueError(f"Missing required values: {', '.join(missing)}")
    
    return (aci_host, aci_username, aci_password, firemon_host, firemon_username, 
            firemon_password, domain_id, device_id)


def main():
    """
    Main function.
    """
    # Parse command-line arguments
    args = parse_arguments()
    
    try:
        # Get credentials
        (aci_host, aci_username, aci_password, firemon_host, firemon_username, 
         firemon_password, domain_id, device_id) = get_credentials(args)
        
        # Step 1: Authenticate with ACI
        print(f"Authenticating with ACI at {aci_host}...")
        aci_cookies = authenticate_aci(aci_host, aci_username, aci_password)
        print(f"Successfully authenticated with ACI at {aci_host}")
        
        # Step 2: Get ACI configuration data
        print(f"Retrieving configuration data from ACI...")
        aci_data = get_aci_data(aci_host, aci_cookies)
        print(f"Successfully retrieved configuration data from ACI")
        
        # Step 3: Authenticate with FireMon
        print(f"Authenticating with FireMon at {firemon_host}...")
        firemon_session = authenticate_firemon(firemon_host, firemon_username, firemon_password)
        print(f"Successfully authenticated with FireMon at {firemon_host}")
        
        # Step 4: Get latest revision ID
        print(f"Getting latest revision ID for device {device_id}...")
        revision_id = get_latest_revision(firemon_host, firemon_session, domain_id, device_id)
        print(f"Latest revision ID for device {device_id} is {revision_id}")
        
        # Step 5: Post files to FireMon
        print(f"Posting configuration files to FireMon...")
        result = post_files_to_firemon(firemon_host, firemon_session, revision_id, aci_data)
        print(f"Successfully posted {result['success']} configuration files to FireMon")
        
        return 0
    except Exception as e:
        print(f"ERROR: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
