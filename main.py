import argparse
import csv
import json
import os
import sys
import requests
import yaml
import urllib3
import time
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
            if k.lower() in sensitive_keys:
                new_dict[k] = "[REDACTED]"
            elif k.lower() == "authorization" and isinstance(v, str) and v.lower().startswith("bearer "):
                new_dict[k] = "Bearer [REDACTED]"
            else:
                new_dict[k] = redact_sensitive_data(v)
        return new_dict
    elif isinstance(data, list):
        return [redact_sensitive_data(item) for item in data]
    return data

def debug_log(label: str, data: any, enabled: bool, redact: bool):
    """Prints formatted debug info."""
    if enabled:
        print(f"\n[DEBUG - {label}]")
        output_data = redact_sensitive_data(data) if redact else data
        if isinstance(output_data, (dict, list)):
            print(json.dumps(output_data, indent=2))
        elif isinstance(data, requests.models.Response):
            print(f"Status Code: {data.status_code}")
            try:
                headers_dict = dict(data.headers)
                print("Headers:", json.dumps(redact_sensitive_data(headers_dict) if redact else headers_dict, indent=2))
                print("Body:", json.dumps(data.json(), indent=2))
            except:
                print(f"Body: {data.text[:500]}...")
        else:
            print(output_data)

def get_rsc_token(config: Dict[str, str], debug: bool, redact: bool) -> str:
    """Authenticates with RSC."""
    auth_url = f"https://{config['RSC_DOMAIN']}/api/client_token"
    payload = {"client_id": config['CLIENT_ID'], "client_secret": config['CLIENT_SECRET']}
    
    debug_log("RSC Token Request", {"url": auth_url, "payload": payload}, debug, redact)
    
    for delay in [1, 2, 4]:
        try:
            response = requests.post(auth_url, json=payload, timeout=15)
            debug_log("RSC Token Response", response, debug, redact)
            if response.status_code == 200:
                return response.json().get("access_token")
        except Exception as e:
            debug_log("RSC Token Request Exception", str(e), debug, redact)
            time.sleep(delay)
    print("Error: RSC Auth failed."); sys.exit(1)

def get_cluster_ip(token: str, rsc_domain: str, cluster_uuid: str, debug: bool, redact: bool) -> Optional[str]:
    """Fallback to find a reachable node IP if defaultAddress is missing."""
    url = f"https://{rsc_domain}/api/graphql"
    query = """
    query GetClusterNodes($id: UUID!) {
      cluster(clusterUuid: $id) {
        clusterNodeConnection {
          nodes { ipAddress status }
        }
      }
    }
    """
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {'query': query, 'variables': {'id': cluster_uuid}}
    
    debug_log("Cluster Node Query", payload, debug, redact)
    
    try:
        res = requests.post(url, json=payload, headers=headers, timeout=15)
        debug_log("Cluster Node Response", res, debug, redact)
        nodes = res.json().get('data', {}).get('cluster', {}).get('clusterNodeConnection', {}).get('nodes', [])
        for node in nodes:
            if node.get('ipAddress') and node.get('status', '').upper() == 'OK':
                return node['ipAddress']
        if nodes: return nodes[0].get('ipAddress')
    except Exception as e:
        debug_log("Cluster Node Exception", str(e), debug, redact)
    return None

def get_cdm_token(cluster_addr: str, config: Dict[str, str], debug: bool, redact: bool) -> Optional[str]:
    """Obtains a session token from a local CDM cluster."""
    url = f"https://{cluster_addr}/api/v1/service_account/session"
    payload = {"serviceAccountId": config['CLIENT_ID'], "secret": config['CLIENT_SECRET']}
    
    debug_log(f"CDM Session Auth Request ({cluster_addr})", payload, debug, redact)
    
    try:
        res = requests.post(url, json=payload, timeout=15, verify=False)
        debug_log(f"CDM Session Auth Response ({cluster_addr})", res, debug, redact)
        return res.json().get("token") if res.status_code == 200 else None
    except Exception as e:
        debug_log(f"CDM Session Auth Exception ({cluster_addr})", str(e), debug, redact)
        return None

def get_vm_details(token: str, rsc_domain: str, vm_name: str, debug: bool, redact: bool) -> Optional[Tuple[str, str]]:
    """Queries RSC for VM UUID and cluster address."""
    url = f"https://{rsc_domain}/api/graphql"
    query = """
    query GetVm($name: String!) {
      vSphereVmNewConnection(filter: [{field: NAME, texts: [$name]}, {field: IS_RELIC, texts: ["false"]}]) {
        nodes { 
          cdmId 
          id 
          name 
          cluster { id defaultAddress } 
        }
      }
    }
    """
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {'query': query, 'variables': {'name': vm_name}}
    
    debug_log("VM Discovery Query", payload, debug, redact)
    
    try:
        res = requests.post(url, json=payload, headers=headers, timeout=15)
        debug_log("VM Discovery Response", res, debug, redact)
        nodes = res.json().get('data', {}).get('vSphereVmNewConnection', {}).get('nodes', [])
        for node in nodes:
            if node['name'].lower() == vm_name.lower():
                raw_id = node.get('cdmId') or node.get('id')
                vm_uuid = raw_id.split(':::')[-1]
                
                cluster = node.get('cluster', {})
                address = cluster.get('defaultAddress')
                
                if not address and cluster.get('id'):
                    address = get_cluster_ip(token, rsc_domain, cluster['id'], debug, redact)
                
                return vm_uuid, address
    except Exception as e:
        debug_log("VM Discovery Exception", str(e), debug, redact)
    return None

def get_actual_pause_state(vm_data: dict) -> Optional[bool]:
    """
    Determines pause state by checking for open-ended snappable blackout windows.
    A manually paused VM in Rubrik shows a window with a startTime but no endTime.
    """
    # 1. Source of Truth: Check snappable blackout windows
    blackout_windows = vm_data.get('blackoutWindows', {}).get('snappableBlackoutWindows', [])
    if blackout_windows:
        # If any window has a startTime but is missing an endTime, it's an active manual pause
        is_paused = any(window.get('startTime') and not window.get('endTime') for window in blackout_windows)
        return is_paused

    # 2. Fallback: blackoutWindowStatus summary flag
    blackout_status = vm_data.get('blackoutWindowStatus', {})
    if 'isSnappableBlackoutActive' in blackout_status:
        return blackout_status['isSnappableBlackoutActive']
    
    # 3. Last Fallback: top-level booleans (might not be present in all responses)
    if 'isVmPaused' in vm_data:
        return vm_data['isVmPaused']
    if 'vmIsPaused' in vm_data:
        return vm_data['vmIsPaused']
        
    return None

def update_vm_pause_status(config: Dict[str, str], cluster_addr: str, vm_uuid: str, vm_name: str, pause_status: bool, debug: bool, redact: bool) -> bool:
    """Sets the pause state via PATCH and verifies via blackout window analysis."""
    if not cluster_addr:
        print(f"Error: Could not resolve a cluster IP for {vm_name}."); return False

    cdm_token = get_cdm_token(cluster_addr, config, debug, redact)
    if not cdm_token:
        print(f"Error: Auth failed for cluster {cluster_addr}"); return False

    vm_id = f"VirtualMachine:::{vm_uuid}"
    url = f"https://{cluster_addr}/api/v1/vmware/vm/{vm_id}"
    headers = {"Authorization": f"Bearer {cdm_token}", "Content-Type": "application/json"}
    
    try:
        # Step 0: PRE-CHECK 
        check_res = requests.get(url, headers=headers, timeout=15, verify=False)
        if check_res.status_code == 200:
            if get_actual_pause_state(check_res.json()) == pause_status:
                print(f"Skip: {vm_name} is already {'Paused' if pause_status else 'Unpaused'}.")
                return True

        # Step 1: ISSUE PATCH COMMAND
        # Since /pause and /resume endpoints returned 404, we use the standard PATCH method.
        payload = {"isVmPaused": pause_status}
        debug_log(f"CDM PATCH - {vm_name}", {"url": url, "payload": payload}, debug, redact)
        res = requests.patch(url, headers=headers, json=payload, timeout=15, verify=False)
        debug_log(f"CDM PATCH Response - {vm_name}", res, debug, redact)
        
        # If isVmPaused failed, try the legacy vmIsPaused field
        if res.status_code not in [200, 202, 204, 422]:
            payload_legacy = {"vmIsPaused": pause_status}
            res = requests.patch(url, headers=headers, json=payload_legacy, timeout=15, verify=False)
            debug_log(f"CDM PATCH Legacy Response - {vm_name}", res, debug, redact)

        if res.status_code not in [200, 202, 204, 422]:
            print(f"Error: Cluster {cluster_addr} returned {res.status_code} during update.")
            return False
            
        # Step 2: VERIFY
        print(f"Verifying {vm_name} state...")
        time.sleep(2) 
        get_res = requests.get(url, headers=headers, timeout=15, verify=False)
        if get_res.status_code == 200:
            actual = get_actual_pause_state(get_res.json())
            if actual == pause_status:
                print(f"VERIFIED: {vm_name} is now {'Paused' if pause_status else 'Unpaused'} (Node: {cluster_addr})")
                return True
            else:
                print(f"VERIFICATION FAILED: [{cluster_addr}] State is {actual}, expected {pause_status}")
                return False
        else:
            print(f"Verification Error: Could not GET VM details for {vm_name}.")
            return False
    except Exception as e:
        print(f"Error connecting to {cluster_addr}: {e}"); return False

def main():
    config = load_config()
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("-r", "--redact", action="store_true")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--pause", action="store_true")
    group.add_argument("-u", "--unpause", action="store_true")
    
    args = parser.parse_args()
    pause_value = True if args.pause else False
    
    vms = []
    with open(args.file, 'r') as f:
        reader = csv.reader(f)
        next(reader, None) # Skip header
        for row in reader:
            if row: vms.append(row[0].strip())

    rsc_token = get_rsc_token(config, args.debug, args.redact)
    success, fail = 0, 0
    for name in vms:
        print(f"\nProcessing: {name}")
        details = get_vm_details(rsc_token, config['RSC_DOMAIN'], name, args.debug, args.redact)
        if details and details[1]:
            if update_vm_pause_status(config, details[1], details[0], name, pause_value, args.debug, args.redact):
                success += 1; continue
        elif details and not details[1]:
            print(f"Error: VM '{name}' found, but cluster address is missing.")
        else:
            print(f"Error: Could not find '{name}' in RSC.")
        fail += 1
            
    print(f"\nSummary - Success: {success}, Fail: {fail}")

if __name__ == "__main__":
    main()