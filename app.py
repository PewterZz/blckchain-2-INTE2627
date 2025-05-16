from flask import Flask, render_template, request, jsonify
import json
import os
import time
from config import (
    INVENTORY_KEYS, PKG_PARAMS, PROCUREMENT_OFFICER_KEYS,
    HARN_IDS, HARN_RANDOM_VALUES, CONSENSUS_THRESHOLD, INVENTORY_IDS
)
from crypto_utils import (
    generate_rsa_keys, rsa_sign, rsa_verify, rsa_encrypt, rsa_decrypt,
    harn_pkg_setup, harn_extract_secret_key, harn_partial_sign,
    harn_aggregate_signatures, harn_verify_multi_sig, harn_hash_msg_rand,
    hash_message_to_int
)
import hashlib

app = Flask(__name__)
DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True) 

RSA_PUBLIC_KEYS = {}
RSA_PRIVATE_KEYS = {}
PKG_PUBLIC_PARAMS = None
PKG_MASTER_SECRET = None
HARN_USER_SECRET_KEYS = {}
OFFICER_PUBLIC_KEY = None
OFFICER_PRIVATE_KEY = None

def initialize_keys():
    """Generate and store all necessary keys on application start."""
    global RSA_PUBLIC_KEYS, RSA_PRIVATE_KEYS, PKG_PUBLIC_PARAMS, \
           PKG_MASTER_SECRET, HARN_USER_SECRET_KEYS, \
           OFFICER_PUBLIC_KEY, OFFICER_PRIVATE_KEY

    print("Initializing cryptographic keys...")

    # 1. Inventory RSA Keys
    for inv_id, keys in INVENTORY_KEYS.items():
        try:
            pub, priv = generate_rsa_keys(keys['p'], keys['q'], keys['e'])
            RSA_PUBLIC_KEYS[inv_id] = pub
            RSA_PRIVATE_KEYS[inv_id] = priv
            print(f"  - Generated RSA keys for Inventory {inv_id}")
        except ValueError as e:
            print(f"Error generating RSA keys for Inventory {inv_id}: {e}")

    # 2. Procurement Officer RSA Keys
    try:
        OFFICER_PUBLIC_KEY, OFFICER_PRIVATE_KEY = generate_rsa_keys(
            PROCUREMENT_OFFICER_KEYS['p'],
            PROCUREMENT_OFFICER_KEYS['q'],
            PROCUREMENT_OFFICER_KEYS['e']
        )
        print("  - Generated RSA keys for Procurement Officer")
    except ValueError as e:
        print(f"Error generating RSA keys for Procurement Officer: {e}")


    # 3. Harn PKG Setup
    try:
        PKG_PUBLIC_PARAMS, PKG_MASTER_SECRET = harn_pkg_setup(
            PKG_PARAMS['p'], PKG_PARAMS['q'], PKG_PARAMS['e']
        )
        print(f"  - Harn PKG Setup complete. PKG Public Params (e, n): {PKG_PUBLIC_PARAMS}")
    except ValueError as e:
        print(f"Error setting up Harn PKG: {e}")


    # 4. Harn User Secret Key Extraction (for Inventories)
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


def save_inventory(inv_id, data):
    """Saves inventory data to its JSON file."""
    path = get_inventory_path(inv_id)
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except IOError as e:
        print(f"Error saving inventory for {inv_id}: {e}")
        return False

@app.route('/')
def index():
    """Renders the main HTML page."""
    return render_template('index.html')

@app.route('/add_record', methods=['POST'])
def add_record():
    """Handles adding a new record: RSA Sign -> Consensus -> Commit."""
    data = request.get_json()
    if not data:
        return jsonify({
            "status": "Error",
            "error": "Missing or invalid JSON data",
            "details": "Please provide all required fields in the correct format."
        }), 400
        
    signer_id = data.get('signer')
    
    # Check for required fields first
    required_fields = ['item_id', 'qty', 'price', 'location']
    missing_fields = [field for field in required_fields if field not in data or data[field] is None]
    if missing_fields:
        return jsonify({
            "status": "Error",
            "error": f"Missing required fields: {', '.join(missing_fields)}",
            "details": "All fields (item_id, qty, price, location) are required."
        }), 400
        
    try:
        qty = int(data.get('qty'))
        price = int(data.get('price'))
    except (ValueError, TypeError):
        return jsonify({
            "status": "Error",
            "error": "Invalid quantity or price: must be integers",
            "details": "Quantity and price must be valid numbers without decimals."
        }), 400
        
    new_record = {
        "id": data.get('item_id'),
        "qty": qty,
        "price": price,
        "location": data.get('location')
    }

    if signer_id not in ['A', 'B', 'C', 'D']:
        return jsonify({
            "status": "Error",
            "error": "Invalid inventory ID. Must be one of A, B, C, or D",
            "details": "The signer must be from one of the authorized inventory nodes."
        }), 400
    if new_record['location'] not in ['A', 'B', 'C', 'D']:
        return jsonify({
            "status": "Error", 
            "error": "Invalid location. Must be one of A, B, C, or D",
            "details": "The item location must be a valid warehouse identifier."
        }), 400
    if not all([signer_id, new_record['id'], new_record['qty'] is not None, new_record['price'] is not None, new_record['location']]):
         return jsonify({
             "status": "Error",
             "error": "Missing required fields",
             "details": "Please ensure all fields have valid values."
         }), 400
    if signer_id not in INVENTORY_IDS:
         return jsonify({
             "status": "Error",
             "error": "Invalid signer inventory ID",
             "details": "The signer ID must be a valid inventory node."
         }), 400

    message = f"ADD:{new_record['id']},{new_record['qty']},{new_record['price']},{new_record['location']}"
    print(f"\n--- Proposing Record ---")
    print(f"Signer: {signer_id}")
    print(f"Record: {new_record}")
    print(f"Message to Sign: {message}")

    # Add timestamp to prevent replay attacks
    timestamp = int(time.time())
    message_with_ts = f"{message}|TS:{timestamp}"
    print(f"Message with timestamp: {message_with_ts}")
    
    # 1. Signing - Add calculation details
    calculation_steps = {
        "key_details": {},
        "signing_steps": {},
        "verification_steps": {}
    }
    
    try:
        private_key = RSA_PRIVATE_KEYS[signer_id]
        d, n = private_key
        
        # Add key details
        pub_key = RSA_PUBLIC_KEYS[signer_id]
        e, n = pub_key
        p, q = INVENTORY_KEYS[signer_id]['p'], INVENTORY_KEYS[signer_id]['q']
        phi_n = (p-1) * (q-1)
        
        calculation_steps["key_details"] = {
            "p": str(p),
            "q": str(q),
            "n": str(n),
            "phi_n": str(phi_n),
            "e": str(e),
            "d": str(d)
        }
        
        # Calculate hash for the message
        msg_hash_int = hash_message_to_int(message_with_ts)
        
        # Sign the message
        signature = rsa_sign(message_with_ts, private_key)
        
        calculation_steps["signing_steps"] = {
            "message": message,
            "message_with_timestamp": message_with_ts,
            "message_hash": str(msg_hash_int),
            "calculation": f"signature = (message_hash)^d mod n = ({msg_hash_int})^{d} mod {n}",
            "signature": str(signature)
        }
        
        print(f"Signature generated by {signer_id}: {signature}")
    except KeyError:
        return jsonify({"error": f"Keys not found for signer {signer_id}"}), 500
    except Exception as e:
        print(f"Signing error: {e}")
        return jsonify({"error": f"Signing failed: {e}"}), 500

    # 2. Consensus Simulation (PoA)
    print("--- Starting Consensus ---")
    validations = 0
    verification_details = {}
    validations += 1
    verification_details[signer_id] = "Self-validated (Signer)"

    signer_public_key = RSA_PUBLIC_KEYS[signer_id]
    for node_id in INVENTORY_IDS:
        if node_id != signer_id:
            print(f"  - Verifying signature by Node {node_id}...")
            try:
                # Verify using message with timestamp
                is_valid = rsa_verify(message_with_ts, signature, signer_public_key)
                verification_details[node_id] = f"Verified: {is_valid}"
                
                # Add verification calculation steps
                e, n = signer_public_key
                decrypted_hash = pow(signature, e, n)
                calculation_steps["verification_steps"][node_id] = {
                    "calculation": f"(signature)^e mod n = ({signature})^{e} mod {n} = {decrypted_hash}",
                    "expected_hash": str(msg_hash_int),
                    "result": "Valid" if is_valid else "Invalid"
                }
                
                if is_valid:
                    validations += 1
                    print(f"  - Node {node_id}: Signature VALID")
                else:
                    print(f"  - Node {node_id}: Signature INVALID")
            except Exception as e:
                 verification_details[node_id] = f"Verification Error: {e}"
                 print(f"  - Node {node_id}: Verification ERROR - {e}")


    print(f"Total Validations: {validations}/{len(INVENTORY_IDS)}")
    print(f"Consensus Threshold: {CONSENSUS_THRESHOLD}")

    # 3. Check Consensus and Commit
    if validations >= CONSENSUS_THRESHOLD:
        print("--- Consensus Reached! Committing Record ---")
        commit_status = {}
        success = True
        for node_id in INVENTORY_IDS:
            inventory_data = load_inventory(node_id)
            if any(item['id'] == new_record['id'] for item in inventory_data):
                 print(f"  - Node {node_id}: Record ID {new_record['id']} already exists. Skipping add.")
                 commit_status[node_id] = "Skipped (ID exists)"
                 continue 

            inventory_data.append(new_record)
            if save_inventory(node_id, inventory_data):
                commit_status[node_id] = "Committed"
                print(f"  - Node {node_id}: Record added successfully.")
            else:
                commit_status[node_id] = "Commit Failed (Save Error)"
                print(f"  - Node {node_id}: Failed to save inventory.")
                success = False 

        if success:
             return jsonify({
                 "status": "Consensus Reached",
                 "message": "Record added to inventories.",
                 "new_record": new_record,
                 "signature": str(signature), 
                 "verification_details": verification_details,
                 "commit_status": commit_status,
                 "timestamp": timestamp,
                 "details": "The record was successfully added to all inventory nodes after consensus validation.",
                 "calculation_steps": calculation_steps
             }), 201 
        else:
             return jsonify({
                 "status": "Consensus Reached but Commit Failed",
                 "message": "Consensus was reached, but saving failed for some nodes.",
                 "new_record": new_record,
                 "signature": str(signature),
                 "verification_details": verification_details,
                 "commit_status": commit_status,
                 "details": "Although consensus was reached, there was an error saving the record to one or more inventory databases."
             }), 500  # Server error
    else:
        print("--- Consensus Failed! Record Rejected ---")
        return jsonify({
            "status": "Consensus Failed",
            "message": "Record rejected due to insufficient validations.",
            "required": CONSENSUS_THRESHOLD,
            "received": validations,
            "signature": str(signature),
            "verification_details": verification_details,
            "details": f"Consensus requires at least {CONSENSUS_THRESHOLD} validations, but only {validations} nodes agreed."
        }), 403  # Forbidden - better status code for consensus rejection


@app.route('/query_item', methods=['POST'])
def query_item():
    """Handles querying a record: Multi-sign -> Encrypt -> Return"""
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
                 # Decide how to handle - skip node or fail query? Fail for now.
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

    if not consistent_record: # Should have been caught earlier, but double-check
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
        
        # Ensure the message used for verification matches the one signed
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
        "verification_status": verification_status
    }), 200

if __name__ == "__main__":
    import socket
    import argparse
    
    initialize_keys()
    
    # Setup command line arguments
    parser = argparse.ArgumentParser(description='Run the Blockchain Inventory System server')
    parser.add_argument('--port', type=int, default=5001, help='Port number to run the server on')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    args = parser.parse_args()
    
    # Find an available port if the specified one is in use
    port = args.port
    max_retry = 5
    retry_count = 0
    
    while retry_count < max_retry:
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.bind(('localhost', port))
            test_socket.close()
            # Port is available
            break
        except socket.error:
            print(f"Port {port} is in use. Trying port {port+1}...")
            port += 1
            retry_count += 1
    
    if retry_count == max_retry:
        print(f"Failed to find an available port after {max_retry} attempts. Please specify a different port.")
        exit(1)
    
    print(f"\n==== Starting Blockchain Inventory Server on port {port} ====")
    print(f"Access the application at http://localhost:{port}")
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=port, debug=args.debug) 
