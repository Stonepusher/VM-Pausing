import argparse
import csv
import json
import os
import sys
import requests
import yaml
import urllib3
from typing import Optional, Dict, List, Tuple

# Suppress InsecureRequestWarning for direct cluster calls
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Constants ---
CONFIG_FILE = "config.yaml"

def load_config() -> Dict[str, str]:
    """Reads RSC credentials from a local YAML file. Creates a template if missing."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, CONFIG_FILE)

    if not os.path.exists(config_path):
        example_config = {
            "RSC_DOMAIN": "your_rsc_domain.rubrik.com",
            "CLIENT_ID": "your_service_account_client_id",
            "CLIENT_SECRET": "your_service_account_client_secret"
        }
        try:
            with open(config_path, 'w') as f:
                f.write("# Rubrik RSC Configuration\n")
                f.write("# Please populate the values below.\n")
                yaml.dump(example_config, f, default_flow_style=False, sort_keys=False)
            
            print(f"\n--- CONFIGURATION REQUIRED ---")
            print(f"The configuration file was missing. I have created a valid YAML template at:")
            print(f"PATH: {config_path}")
            print(f"------------------------------\n")
            print("Please update the file with your credentials and run the script again.")
            sys.exit(0)
        except Exception as e:
            print(f"Error creating config template at {config_path}: {e}")
            sys.exit(1)

    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            
        if config is None or not isinstance(config, dict):
            print(f"Error: {config_path} format is invalid.")
            sys.exit(1)
            
        required_keys = ["RSC_DOMAIN", "CLIENT_ID", "CLIENT_SECRET"]
        for key in required_keys:
            val = config.get(key)
            if not isinstance(val, str) or not val.strip():
                print(f"Error: Key '{key}' in {config_path} must be a non-empty string.")
                sys.exit(1)
            
            if key == "RSC_DOMAIN" and "://" in val:
                print(f"Error: RSC_DOMAIN should only be the FQDN. Remove 'https://'.")
                sys.exit(1)

        return config
    except Exception as e:
        print(f"Unexpected error reading {config_path}: {e}")
        sys.exit(1)

def redact_sensitive_data(data: any) -> any:
    """Recursively redacts sensitive keys and bearer tokens from dictionaries and lists."""
    sensitive_keys = {"client_id", "client_secret", "access_token", "token", "serviceaccountid", "secret"}
    
    if isinstance(data, dict):
        new_dict = {}
        for k, v in data.items():
            k_low = k.lower()
            if k_low in sensitive_keys:
                new_dict[k] = "[REDACTED]"
            elif k_low == "authorization" and isinstance(v, str) and v.lower().startswith("bearer "):
                new_dict[k] = "Bearer [REDACTED]"
            elif k_low == "x-rubrik-auth-token":
                new_dict[k] = "[REDACTED]"
            else:
                new_dict[k] = redact_sensitive_data(v)
        return new_dict
    elif isinstance(data, list):
        return [redact_sensitive_data(item) for item in data]
    return data

def debug_log(label: str, data: any, enabled: bool, redact: bool):
    """Helper to print formatted debug information. Redacts if 'redact' is True."""
    if enabled:
        print(f"\n[DEBUG - {label}]")
        
        # Determine if we should redact based on the flag
        output_data = redact_sensitive_data(data) if redact else data
        
        if isinstance(output_data, (dict, list)):
            print(json.dumps(output_data, indent=2))
        elif isinstance(data, requests.models.Response):
            # Special handling for Response objects
            print(f"Status Code: {data.status_code}")
            print("Headers:")
            headers_dict = dict(data.headers)
            print(json.dumps(redact_sensitive_data(headers_dict) if redact else headers_dict, indent=2))
            print("Body:")
            try:
                body_json = data.json()
                print(json.dumps(redact_sensitive_data(body_json) if redact else body_json, indent=2))
            except ValueError:
                print("[Non-JSON Body Content]")
        else:
            print(output_data)

def get_rsc_token(config: Dict[str, str], debug: bool, redact: bool) -> str:
    """Authenticates with RSC using Service Account credentials."""
    auth_url = f"https://{config['RSC_DOMAIN']}/api/client_token"
    payload = {
        "client_id": config['CLIENT_ID'],
        "client_secret": config['CLIENT_SECRET'],
        "name": "RSC_Dynamic_Cluster_Automation"
    }
    
    debug_log("RSC Auth Request URL", auth_url, debug, redact)
    debug_log("RSC Auth Payload", payload, debug, redact)
    
    import time
    for delay in [1, 2, 4, 8, 16]:
        try:
            response = requests.post(auth_url, json=payload, timeout=15)
            debug_log("RSC Auth Raw Response", response, debug, redact)
            # If we get a 200, return the token
            if response.status_code == 200:
                res_json = response.json()
                return res_json.get("access_token")
            # Otherwise, raise for status to trigger retry if it's a transient error
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            debug_log("RSC Auth Attempt Error", str(e), debug, redact)
            time.sleep(delay)
    
    print("Error: Failed to authenticate with RSC after multiple retries.")
    sys.exit(1)

def get_cdm_token(cluster_addr: str, config: Dict[str, str], debug: bool, redact: bool) -> Optional[str]:
    """Obtains a session token from a local CDM cluster using RSC Service Account credentials."""
    cdm_auth_url = f"https://{cluster_addr}/api/v1/service_account/session"
    payload = {
        "serviceAccountId": config['CLIENT_ID'],
        "secret": config['CLIENT_SECRET']
    }

    debug_log("CDM Service Account Auth Request URL", cdm_auth_url, debug, redact)
    debug_log("CDM Service Account Auth Payload", payload, debug, redact)

    try:
        response = requests.post(cdm_auth_url, json=payload, timeout=15, verify=False)
        debug_log("CDM Service Account Auth Raw Response", response, debug, redact)
        
        if response.status_code == 200:
            token = response.json().get("token")
            if token and token != "null":
                return token
        
        print(f"Error: CDM authentication failed on {cluster_addr} (Status: {response.status_code})")
        return None
    except Exception as e:
        print(f"Error: Failed to connect to CDM for authentication on {cluster_addr}: {e}")
        return None

def get_cluster_ip(token: str, rsc_domain: str, cluster_uuid: str, debug: bool, redact: bool) -> Optional[str]:
    """
    Issues a ClusterDetailQuery to find a reachable IP address for a cluster node.
    """
    graphql_url = f"https://{rsc_domain}/api/graphql"
    
    query = """
    query GetClusterNodes($id: UUID!) {
      cluster(clusterUuid: $id) {
        id
        name
        defaultAddress
        clusterNodeConnection {
          nodes {
            ipAddress
            status
          }
        }
      }
    }
    """
    
    variables = {"id": cluster_uuid}
    headers = {
        "Authorization": f"Bearer {token}", 
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    payload = {'query': query, 'variables': variables}
    debug_log("Cluster Discovery Request", payload, debug, redact)
    
    try:
        response = requests.post(graphql_url, json=payload, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()
        debug_log("Cluster Discovery Response", data, debug, redact)
        
        cluster = data.get('data', {}).get('cluster', {})
        if not cluster:
            return None
            
        if cluster.get('defaultAddress'):
            return cluster['defaultAddress']
            
        nodes = cluster.get('clusterNodeConnection', {}).get('nodes', [])
        for node in nodes:
            if node.get('ipAddress') and node.get('status', '').upper() == 'OK':
                return node['ipAddress']
        
        if nodes and nodes[0].get('ipAddress'):
            return nodes[0]['ipAddress']
            
        return None
    except Exception as e:
        debug_log("Cluster Discovery Error", str(e), debug, redact)
        return None

def get_vm_details(token: str, rsc_domain: str, vm_name: str, debug: bool, redact: bool) -> Optional[Tuple[str, str, str]]:
    """Queries RSC GraphQL API for VM RSC ID, CDM ID, and CDM cluster address."""
    graphql_url = f"https://{rsc_domain}/api/graphql"
    
    query = """
    query GetVmDetails($name: String!) {
      vSphereVmNewConnection(filter: [
        {field: NAME, texts: [$name]},
        {field: IS_RELIC, texts: ["false"]}
      ]) {
        nodes {
          id
          cdmId
          name
          cluster {
            id
            name
            defaultAddress
          }
        }
      }
    }
    """
    
    variables = {"name": vm_name}
    headers = {
        "Authorization": f"Bearer {token}", 
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    raw_payload = {'query': query, 'variables': variables}
    debug_log("GraphQL Request URL", graphql_url, debug, redact)
    debug_log("GraphQL Request Headers", headers, debug, redact)
    debug_log("GraphQL Request Payload", raw_payload, debug, redact)
    
    try:
        response = requests.post(
            graphql_url, 
            json=raw_payload, 
            headers=headers,
            timeout=15
        )
        debug_log("GraphQL Raw Response", response, debug, redact)
        response.raise_for_status()
        data = response.json()
        
        nodes = data.get('data', {}).get('vSphereVmNewConnection', {}).get('nodes', [])
        if not nodes:
            return None
        
        for node in nodes:
            if node['name'].lower() == vm_name.lower():
                rsc_vm_id = node['id']
                cdm_vm_id = node.get('cdmId')
                cluster = node.get('cluster', {})
                cluster_uuid = cluster.get('id')
                cluster_address = cluster.get('defaultAddress')
                
                target_vm_id = cdm_vm_id if cdm_vm_id else rsc_vm_id

                if not cluster_address and cluster_uuid:
                    print(f"Info: Cluster address missing in VM metadata. Discovering node IPs for cluster '{cluster.get('name')}'...")
                    cluster_address = get_cluster_ip(token, rsc_domain, cluster_uuid, debug, redact)
                
                if not cluster_address:
                    print(f"Warning: VM '{vm_name}' resolved to cluster '{cluster.get('name')}', but no connection address or node IPs were found.")
                    return None
                    
                return rsc_vm_id, target_vm_id, cluster_address
                
        return None
    except Exception as e:
        print(f"Error querying GraphQL for {vm_name}: {e}")
        return None

def update_vm_pause_status(config: Dict[str, str], cluster_addr: str, vm_id: str, vm_name: str, pause_status: bool, debug: bool, redact: bool) -> bool:
    """Obtains a cluster-specific token and sends PATCH request to the CDM Cluster."""
    if not cluster_addr or cluster_addr.lower() == 'none':
        print(f"Error: Invalid cluster address provided for {vm_name}. Cannot issue REST call.")
        return False

    # 1. Obtain a cluster-specific token using Client ID/Secret via service_account/session
    cdm_token = get_cdm_token(cluster_addr, config, debug, redact)
    if not cdm_token:
        print(f"Error: Could not authenticate with cluster {cluster_addr}.")
        return False

    # 2. Prep the VM ID for the CDM API call (requires VirtualMachine::: prefix)
    target_cdm_vm_id = f"VirtualMachine:::{vm_id}" if "VirtualMachine:::" not in vm_id else vm_id

    # 3. Issue the PATCH call using the cluster-specific token
    cdm_url = f"https://{cluster_addr}/api/v1/vmware/vm/{target_cdm_vm_id}"
    headers = {
        "Authorization": f"Bearer {cdm_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    data = {"vmIsPaused": pause_status}
    
    debug_log("CDM REST Request URL", cdm_url, debug, redact)
    debug_log("CDM REST Request Headers", headers, debug, redact)
    debug_log("CDM REST Request Payload", data, debug, redact)
    
    try:
        response = requests.patch(cdm_url, headers=headers, json=data, timeout=15, verify=False)
        debug_log("CDM REST Raw Response", response, debug, redact)
        
        if response.status_code == 200:
            action = "Paused" if pause_status else "Unpaused"
            print(f"Success: [{cluster_addr}] {action} {vm_name}")
            return True
        else:
            print(f"Failed to update {vm_name} on {cluster_addr}: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"Error connecting to cluster {cluster_addr} for {vm_name}: {e}")
        return False

def validate_csv(filepath: str) -> List[Dict[str, str]]:
    """Extracts VM data and skips headers."""
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        sys.exit(1)
        
    vm_data_list = []
    try:
        with open(filepath, mode='r', encoding='utf-8') as f:
            sample = f.read(2048)
            f.seek(0)
            sniffer = csv.Sniffer()
            dialect = sniffer.sniff(sample)
            has_header = sniffer.has_header(sample)
            reader = csv.reader(f, dialect)
            
            if has_header:
                next(reader)
            
            for row in reader:
                if row:
                    vm_name = row[0].strip()
                    if not vm_name or vm_name.lower() in ["vm_name", "name", "vm name", "virtual machine"]:
                        continue
                    
                    provided_id = next((cell.strip() for cell in row[1:] if cell.strip().startswith("VmwareVm:::")), None)
                    vm_data_list.append({"name": vm_name, "provided_id": provided_id})
                        
    except Exception as e:
        print(f"Error parsing CSV: {e}")
        sys.exit(1)
        
    return vm_data_list

def main():
    config = load_config()

    parser = argparse.ArgumentParser(description="Batch pause/unpause Rubrik backups via CSV.")
    parser.add_argument("-f", "--file", required=True, help="Path to the source CSV file.")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable verbose debug logging of API calls.")
    parser.add_argument("-r", "--redact", action="store_true", help="Redact sensitive info (IDs, secrets, tokens) from debug output.")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--pause", action="store_true", help="Pause backups (vmIsPaused: True).")
    group.add_argument("-u", "--unpause", action="store_true", help="Unpause backups (vmIsPaused: False).")
    
    args = parser.parse_args()
    pause_value = True if args.pause else False
    
    vm_list = validate_csv(args.file)
    print(f"Loaded {len(vm_list)} VM entries. Action: {'Pausing' if pause_value else 'Unpausing'} VMs.")
    
    # RSC Authentication
    rsc_token = get_rsc_token(config, args.debug, args.redact)
    
    success, fail = 0, 0
    for vm in vm_list:
        print(f"\nProcessing: {vm['name']}")
        
        # Discovery via RSC
        details = get_vm_details(rsc_token, config['RSC_DOMAIN'], vm['name'], args.debug, args.redact)
        
        if not details:
            print(f"Warning: Could not resolve '{vm['name']}' in RSC or find its cluster address.")
            fail += 1
            continue
            
        rsc_vm_id, cdm_vm_id, cluster_addr = details
        
        # ID checks
        if vm['provided_id'] and vm['provided_id'] != rsc_vm_id:
            print(f"CRITICAL: ID mismatch for '{vm['name']}'!")
            print(f"  CSV ID: {vm['provided_id']}")
            print(f"  RSC ID: {rsc_vm_id}")
            print(f"  Skipping this VM to prevent accidental update.")
            fail += 1
            continue
        
        # CDM Cluster Update
        if update_vm_pause_status(config, cluster_addr, cdm_vm_id, vm['name'], pause_value, args.debug, args.redact):
            success += 1
        else:
            fail += 1
            
    print(f"\nDone. Success: {success}, Fail: {fail}")

if __name__ == "__main__":
    main()