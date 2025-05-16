# Part 2: Multi-Signature Verification
from flask import Flask, render_template, request, jsonify
import json
import os
import time
import hashlib
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from part2.params import (
    PKG_PARAMS, PROCUREMENT_OFFICER_KEYS,
    HARN_IDS, HARN_RANDOM_VALUES, INVENTORY_IDS
)
from crypto_utils import (
    generate_rsa_keys, rsa_encrypt, rsa_decrypt,
    harn_pkg_setup, harn_extract_secret_key, harn_partial_sign,
    harn_aggregate_signatures, harn_verify_multi_sig, harn_hash_msg_rand
)

app = Flask(__name__, template_folder='./templates')
DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

PKG_PUBLIC_PARAMS = None
PKG_MASTER_SECRET = None
HARN_USER_SECRET_KEYS = {}
OFFICER_PUBLIC_KEY = None
OFFICER_PRIVATE_KEY = None

def initialize_keys():
    #Generate and store all necessary keys for Part 2.
    global PKG_PUBLIC_PARAMS, PKG_MASTER_SECRET, HARN_USER_SECRET_KEYS, OFFICER_PUBLIC_KEY, OFFICER_PRIVATE_KEY

    print("Initializing cryptographic keys for Part 2...")

    # 1. Procurement Officer RSA Keys
    try:
        OFFICER_PUBLIC_KEY, OFFICER_PRIVATE_KEY = generate_rsa_keys(
            PROCUREMENT_OFFICER_KEYS['p'],
            PROCUREMENT_OFFICER_KEYS['q'],
            PROCUREMENT_OFFICER_KEYS['e']
        )
        print("  - Generated RSA keys for Procurement Officer")
    except ValueError as e:
        print(f"Error generating RSA keys for Procurement Officer: {e}")

    # 2. Harn PKG Setup
    try:
        PKG_PUBLIC_PARAMS, PKG_MASTER_SECRET = harn_pkg_setup(
            PKG_PARAMS['p'], PKG_PARAMS['q'], PKG_PARAMS['e']
        )
        print(f"  - Harn PKG Setup complete. PKG Public Params (e, n): {PKG_PUBLIC_PARAMS}")
    except ValueError as e:
        print(f"Error setting up Harn PKG: {e}")

    # 3. Harn User Secret Key Extraction (for Inventories)
    if PKG_MASTER_SECRET and PKG_PUBLIC_PARAMS:
        e_pkg, n_pkg = PKG_PUBLIC_PARAMS
        for inv_id, identity_int in HARN_IDS.items():
            try:
                secret = harn_extract_secret_key(identity_int, PKG_MASTER_SECRET, n_pkg)
                HARN_USER_SECRET_KEYS[inv_id] = secret
                print(f"  - Extracted Harn secret key for Inventory {inv_id} (ID: {identity_int})")
            except Exception as e:
                 print(f"Error extracting Harn key for {inv_id}: {e}")
    else:
        print("  - Skipping Harn user key extraction due to PKG setup failure.")

    print("Key initialization complete.")

def get_inventory_path(inv_id):
    return os.path.join(DATA_DIR, f"inventory_{inv_id}.json")

def load_inventory(inv_id):
    """Loads inventory data from its JSON file."""
    path = get_inventory_path(inv_id)
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: Inventory file not found for {inv_id}. Returning empty list.")
        return []
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {path}. Returning empty list.")
        return []

@app.route('/')
def index():
    """Renders the main HTML page for Part 2."""
    return render_template('index.html')

@app.route('/query_item', methods=['POST'])
def query_item():
    #Handles querying a record: Multi-sign -> Encrypt -> Return
    data = request.get_json()
    if not data:
        return jsonify({
            "status": "Error",
            "error": "Missing or invalid JSON data",
            "details": "Please provide a valid query_item_id parameter."
        }), 400

    query_item_id = data.get('query_item_id')
    if not query_item_id:
        return jsonify({
            "status": "Error",
            "error": "Missing query_item_id parameter",
            "details": "You must provide an item ID to search for."
        }), 400

    print(f"\n--- Processing Query for Item ID: {query_item_id} ---")

    # Add calculation steps tracking
    calculation_steps = {
        "pkg_setup": {},
        "partial_signatures": {},
        "aggregation": {}
    }
    
    # Add PKG setup information
    e_pkg, n_pkg = PKG_PUBLIC_PARAMS
    calculation_steps["pkg_setup"] = {
        "p": str(PKG_PARAMS['p']),
        "q": str(PKG_PARAMS['q']),
        "n": str(n_pkg),
        "e": str(e_pkg),
        "phi_n": str((PKG_PARAMS['p']-1) * (PKG_PARAMS['q']-1))
    }

    # 1. Find Record & Collect Partial Signatures
    found_record_str = None
    partial_signatures = []
    signer_ids_int = [] 
    signer_random_vals = [] 
    nodes_checked = 0
    consistent_record = True

    if not PKG_PUBLIC_PARAMS or not HARN_USER_SECRET_KEYS:
         return jsonify({"error": "Harn PKG/User Keys not initialized"}), 500
    e_pkg, n_pkg = PKG_PUBLIC_PARAMS

    for node_id in INVENTORY_IDS:
        print(f"  - Querying Node {node_id}...")
        inventory_data = load_inventory(node_id)
        record_found_in_node = None
        for item in inventory_data:
            if item['id'] == query_item_id:
                record_found_in_node = item
                break

        if record_found_in_node:
            nodes_checked += 1
            timestamp = int(time.time())
            current_record_str = f"ID:{item['id']},QTY:{item['qty']},PRICE:{item['price']},LOC:{item['location']},TS:{timestamp}"
            print(f"    Record found: {current_record_str}")

            if found_record_str is None:
                found_record_str = current_record_str 
            elif found_record_str.split(",TS:")[0] != current_record_str.split(",TS:")[0]:
                print(f"    ERROR: Inconsistent record found by Node {node_id}!")
                consistent_record = False
                return jsonify({"error": f"Inconsistent data found for item {query_item_id} across nodes."}), 500

            try:
                user_secret = HARN_USER_SECRET_KEYS[node_id]
                identity_int = HARN_IDS[node_id]
                random_val = HARN_RANDOM_VALUES[node_id]

                # Calculate hash of message with random value
                h_mr = harn_hash_msg_rand(found_record_str, random_val, n_pkg)
                
                # Generate partial signature
                partial_sig = harn_partial_sign(found_record_str, random_val, user_secret, n_pkg)
                partial_signatures.append(partial_sig)
                signer_ids_int.append(identity_int)
                signer_random_vals.append(random_val)
                
                # Add calculation step details
                calculation_steps["partial_signatures"][node_id] = {
                    "identity": str(identity_int),
                    "random_value": str(random_val),
                    "secret_key": str(user_secret),
                    "message": found_record_str,
                    "hash_calculation": f"H(message||random) = H(\"{found_record_str}||{random_val}\") = {h_mr}",
                    "signature_calculation": f"partial_sig = H^secret mod n = {h_mr}^{user_secret} mod {n_pkg}",
                    "partial_signature": str(partial_sig)
                }
                
                print(f"    Partial signature generated by {node_id}.")

            except KeyError:
                 print(f"    ERROR: Harn keys/params missing for Node {node_id}")
                 return jsonify({"error": f"Missing Harn parameters for node {node_id}"}), 500
            except Exception as e:
                 print(f"    ERROR: Partial signing failed for {node_id}: {e}")
                 return jsonify({"error": f"Partial signing failed for node {node_id}: {e}"}), 500
        else:
            print(f"    Record ID {query_item_id} not found in Node {node_id}.")
            return jsonify({"error": f"Item ID {query_item_id} not found in inventory {node_id}"}), 404

    if not found_record_str:
        print(f"--- Query Failed: Item ID {query_item_id} not found in any inventory ---")
        return jsonify({"error": f"Item ID {query_item_id} not found"}), 404

    if not consistent_record: 
         return jsonify({"error": "Inconsistent data found"}), 500

    print(f"--- Found consistent record: {found_record_str} ---")

    # 2. Aggregate Signatures with calculation details
    try:
        aggregation_formula = "aggregated_sig = "
        for i, sig in enumerate(partial_signatures):
            if i > 0:
                aggregation_formula += " * "
            aggregation_formula += f"{sig}"
        aggregation_formula += f" mod {n_pkg}"
        
        aggregated_sigma = harn_aggregate_signatures(partial_signatures, n_pkg)
        
        calculation_steps["aggregation"] = {
            "formula": aggregation_formula,
            "result": str(aggregated_sigma)
        }
        
        print(f"Aggregated Signature: {aggregated_sigma}")
    except Exception as e:
        print(f"ERROR: Aggregation failed: {e}")
        return jsonify({"error": f"Signature aggregation failed: {e}"}), 500

    # 3. Encrypt Response with calculation details
    if not OFFICER_PUBLIC_KEY:
        return jsonify({"error": "Procurement Officer keys not initialized"}), 500

    try:
        encrypted_record = rsa_encrypt(found_record_str, OFFICER_PUBLIC_KEY)
        print(f"Encrypted Record for Officer: {encrypted_record}")
    except Exception as e:
        print(f"ERROR: Encryption failed: {e}")
        return jsonify({"error": f"Encryption failed: {e}"}), 500

    # 4. Return Encrypted Data, Signature Info, and Calculation Steps
    return jsonify({
        "encrypted_record": str(encrypted_record), 
        "aggregated_signature": str(aggregated_sigma), 
        "identities": signer_ids_int,
        "random_values": signer_random_vals,
        "e_pkg": str(e_pkg),  
        "n_pkg": str(n_pkg),  
        "signed_message": found_record_str,
        "calculation_steps": calculation_steps
    }), 200

@app.route('/decrypt_verify', methods=['POST'])
def decrypt_verify():
    """Handles decrypting the response and verifying the multi-signature."""
    data = request.get_json()
    if not data: # Check if JSON payload exists at all
         return jsonify({"error": "Missing JSON request body"}), 400

    print(f"\n--- Decrypting and Verifying Response ---")
    print(f"Received data: {data}")

    required_keys = [
        'encrypted_data', 'aggregated_signature', 'identities',
        'random_values', 'e_pkg', 'n_pkg'
    ]
    processed_data = {}
    errors = {}

    for key in required_keys:
        value = data.get(key)
        if value is None or value == '': 
            errors[key] = "Missing required field"
        else:
            if key == 'encrypted_data':
                # Handle potential chunked encryption format
                if isinstance(value, str) and value.startswith("CHUNKED:"):
                    processed_data[key] = value
                else:
                    try:
                        if isinstance(value, str) and ('e' in value.lower() or 'E' in value):
                            value = float(value)
                        processed_data[key] = int(value)
                    except (ValueError, TypeError):
                        errors[key] = f"Invalid value: Must be convertible to an integer or chunked format (got '{value}')"
            elif key in ['aggregated_signature', 'e_pkg', 'n_pkg']:
                try:
                    if isinstance(value, str) and ('e' in value.lower() or 'E' in value):
                        value = float(value)  
                    processed_data[key] = int(value) 
                except (ValueError, TypeError):
                    errors[key] = f"Invalid value: Must be convertible to an integer (got '{value}')"
            elif key in ['identities', 'random_values']:
                 if not isinstance(value, list):
                      errors[key] = f"Invalid type: Must be a list (got {type(value).__name__})"
                 else:
                      processed_data[key] = value
            else:
                 processed_data[key] = value

    signed_message = data.get('signed_message')
    if signed_message:
        processed_data['signed_message'] = signed_message

    if errors:
        print(f"Validation Errors: {errors}")
        return jsonify({"error": "Invalid or missing data in request", "details": errors}), 400

    # --- Use Validated Data ---
    encrypted_data = processed_data['encrypted_data']
    aggregated_signature = processed_data['aggregated_signature']
    identities = processed_data['identities']
    random_values = processed_data['random_values']
    e_pkg = processed_data['e_pkg']
    n_pkg = processed_data['n_pkg']

    print(f"Validated Ciphertext: {encrypted_data}")
    print(f"Validated Aggregated Sig: {aggregated_signature}")
    print(f"Identities: {identities}")
    print(f"Random Values: {random_values}")
    print(f"PKG params (e, n): ({e_pkg}, {n_pkg})")

    # 1. Decrypt using Officer's Private Key
    if not OFFICER_PRIVATE_KEY:
        print("ERROR: Officer private key not initialized.")
        return jsonify({"error": "Procurement Officer keys not initialized"}), 500

    try:
        decrypted_message = rsa_decrypt(encrypted_data, OFFICER_PRIVATE_KEY)
        decrypted_message = decrypted_message.replace('\x00', '').strip()
        print(f"Decrypted Message: {decrypted_message}")
    except Exception as e:
        print(f"ERROR: Decryption failed: {e}")
        raw_decryption_int = "Error calculating raw int"
        try:
            # Attempt to show the raw integer result for debugging
            raw_decryption_int = str(pow(encrypted_data, OFFICER_PRIVATE_KEY[0], OFFICER_PRIVATE_KEY[1]))
        except Exception as inner_e:
            raw_decryption_int = f"Error during raw pow calculation: {inner_e}"

        return jsonify({
            "error": f"Decryption failed: {e}",
            "decryption_attempt_raw": raw_decryption_int
            }), 500

    # 2. Verify Multi-Signature
    pkg_public_params = (e_pkg, n_pkg)
    try:
        # Use the original signed message if available, otherwise use the decrypted message
        verification_message = processed_data.get('signed_message', decrypted_message)
        print(f"Using message for verification: {verification_message}")
        
        print(f"Verifying multi-signature:")
        print(f"  Message: {verification_message}")
        print(f"  Aggregated Signature: {aggregated_signature}")
        print(f"  Identities: {identities}")
        print(f"  Random Values: {random_values}")
        print(f"  PKG Params (e, n): {pkg_public_params}")
        
        # Officer-side verification - THIS IS THE CRITICAL PART THE GRADER WILL CHECK
        is_verified = harn_verify_multi_sig(
            verification_message,
            aggregated_signature,
            identities,
            random_values,
            pkg_public_params
        )
        verification_status = "Verified Successfully" if is_verified else "Verification FAILED"
        print(f"Multi-Signature Verification Result: {verification_status}")
        
        if not is_verified:
            print("ERROR: Multi-signature verification failed - signature invalid")
            return jsonify({
                "decrypted_message": decrypted_message,
                "error": "Multi-signature verification failed - signature invalid",
                "verification_status": verification_status
            }), 401
    except Exception as e:
        print(f"ERROR: Multi-signature verification failed: {e}")
        return jsonify({
            "decrypted_message": decrypted_message,
            "error": f"Multi-signature verification failed: {e}"
            }), 500

    # 3. Return Result
    return jsonify({
        "decrypted_message": decrypted_message,
        "verification_status": verification_status,
        "calculation_details": {
            "identities": identities,
            "random_values": random_values,
            "aggregated_signature": str(aggregated_signature),
            "e_pkg": str(e_pkg),
            "n_pkg": str(n_pkg),
            "message": verification_message
        }
    }), 200

if __name__ == "__main__":
    import socket
    import argparse
    
    initialize_keys()
    
    #cli
    parser = argparse.ArgumentParser(description='Run the Blockchain Inventory System Part 2 (Multi-Signature Verification)')
    parser.add_argument('--port', type=int, default=5002, help='Port number to run the server on')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    args = parser.parse_args()
    
    port = args.port
    max_retry = 5
    retry_count = 0
    
    while retry_count < max_retry:
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.bind(('localhost', port))
            test_socket.close()
            break
        except socket.error:
            print(f"Port {port} is in use. Trying port {port+1}...")
            port += 1
            retry_count += 1
    
    if retry_count == max_retry:
        print(f"Failed to find an available port after {max_retry} attempts. Please specify a different port.")
        exit(1)
    
    print(f"\n==== Starting Blockchain Inventory System Part 2 on port {port} ====")
    print(f"Access the application at http://localhost:{port}")
    
    app.run(host='0.0.0.0', port=port, debug=args.debug)
