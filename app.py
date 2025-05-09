from flask import Flask, render_template, request, jsonify
import json
import os
from config import (
    INVENTORY_KEYS, PKG_PARAMS, PROCUREMENT_OFFICER_KEYS,
    HARN_IDS, HARN_RANDOM_VALUES, CONSENSUS_THRESHOLD, INVENTORY_IDS
)
from crypto_utils import (
    generate_rsa_keys, rsa_sign, rsa_verify, rsa_encrypt, rsa_decrypt,
    harn_pkg_setup, harn_extract_secret_key, harn_partial_sign,
    harn_aggregate_signatures, harn_verify_multi_sig
)

app = Flask(__name__)
DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True) # Ensure data directory exists

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
        # If file doesn't exist, maybe create it with initial data?
        # For now, return empty. Ensure initial files exist.
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
    signer_id = data.get('signer')
    new_record = {
        "id": data.get('item_id'),
        "qty": int(data.get('qty')),
        "price": int(data.get('price')),
        "location": data.get('location')
    }

    if not all([signer_id, new_record['id'], new_record['qty'] is not None, new_record['price'] is not None, new_record['location']]):
         return jsonify({"error": "Missing required fields"}), 400
    if signer_id not in INVENTORY_IDS:
         return jsonify({"error": "Invalid signer inventory ID"}), 400

    message = f"ADD:{new_record['id']},{new_record['qty']},{new_record['price']},{new_record['location']}"
    print(f"\n--- Proposing Record ---")
    print(f"Signer: {signer_id}")
    print(f"Record: {new_record}")
    print(f"Message to Sign: {message}")

    # 1. Signing
    try:
        private_key = RSA_PRIVATE_KEYS[signer_id]
        signature = rsa_sign(message, private_key)
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
    # The signer implicitly validates its own proposal
    validations += 1
    verification_details[signer_id] = "Self-validated (Signer)"

    # Simulate broadcasting to other nodes and verifying
    signer_public_key = RSA_PUBLIC_KEYS[signer_id]
    for node_id in INVENTORY_IDS:
        if node_id != signer_id:
            print(f"  - Verifying signature by Node {node_id}...")
            try:
                is_valid = rsa_verify(message, signature, signer_public_key)
                verification_details[node_id] = f"Verified: {is_valid}"
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
            # Prevent adding duplicate IDs (simple check)
            if any(item['id'] == new_record['id'] for item in inventory_data):
                 print(f"  - Node {node_id}: Record ID {new_record['id']} already exists. Skipping add.")
                 commit_status[node_id] = "Skipped (ID exists)"
                 continue # Or handle as error depending on requirements

            inventory_data.append(new_record)
            if save_inventory(node_id, inventory_data):
                commit_status[node_id] = "Committed"
                print(f"  - Node {node_id}: Record added successfully.")
            else:
                commit_status[node_id] = "Commit Failed (Save Error)"
                print(f"  - Node {node_id}: Failed to save inventory.")
                success = False # Mark overall success as false if any save fails

        if success:
             return jsonify({
                 "status": "Consensus Reached",
                 "message": "Record added to inventories.",
                 "new_record": new_record,
                 "signature": str(signature), # Convert large int to string for JSON
                 "verification_details": verification_details,
                 "commit_status": commit_status
             }), 200
        else:
             return jsonify({
                 "status": "Consensus Reached but Commit Failed",
                 "message": "Consensus was reached, but saving failed for some nodes.",
                 "new_record": new_record,
                 "signature": str(signature),
                 "verification_details": verification_details,
                 "commit_status": commit_status
             }), 500
    else:
        print("--- Consensus Failed! Record Rejected ---")
        return jsonify({
            "status": "Consensus Failed",
            "message": "Record rejected due to insufficient validations.",
            "required": CONSENSUS_THRESHOLD,
            "received": validations,
            "signature": str(signature),
            "verification_details": verification_details
        }), 400


@app.route('/query_item', methods=['POST'])
def query_item():
    """Handles querying an item: Fetch -> Multi-Sign -> Encrypt Response."""
    data = request.get_json()
    item_id_to_query = data.get('query_item_id')

    if not item_id_to_query:
        return jsonify({"error": "Missing item ID to query"}), 400

    print(f"\n--- Processing Query for Item ID: {item_id_to_query} ---")

    # 1. Find Record & Collect Partial Signatures
    found_record_str = None
    partial_signatures = []
    signer_ids_int = [] # Store integer IDs used for signing
    signer_random_vals = [] # Store random values used
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
            if item['id'] == item_id_to_query:
                record_found_in_node = item
                break

        if record_found_in_node:
            nodes_checked += 1
            # Use a consistent string representation for signing
            current_record_str = f"ID:{item['id']},QTY:{item['qty']},PRICE:{item['price']},LOC:{item['location']}"
            print(f"    Record found: {current_record_str}")

            if found_record_str is None:
                found_record_str = current_record_str # Set based on first find
            elif found_record_str != current_record_str:
                print(f"    ERROR: Inconsistent record found by Node {node_id}!")
                consistent_record = False
                # Decide how to handle inconsistency - stop or report? Stop for now.
                return jsonify({"error": f"Inconsistent data found for item {item_id_to_query} across nodes."}), 500

            # Generate partial signature
            try:
                user_secret = HARN_USER_SECRET_KEYS[node_id]
                identity_int = HARN_IDS[node_id]
                random_val = HARN_RANDOM_VALUES[node_id]

                partial_sig = harn_partial_sign(found_record_str, random_val, user_secret, n_pkg)
                partial_signatures.append(partial_sig)
                signer_ids_int.append(identity_int)
                signer_random_vals.append(random_val)
                print(f"    Partial signature generated by {node_id}.")

            except KeyError:
                 print(f"    ERROR: Harn keys/params missing for Node {node_id}")
                 # Decide how to handle - skip node or fail query? Fail for now.
                 return jsonify({"error": f"Missing Harn parameters for node {node_id}"}), 500
            except Exception as e:
                 print(f"    ERROR: Partial signing failed for {node_id}: {e}")
                 return jsonify({"error": f"Partial signing failed for node {node_id}: {e}"}), 500
        else:
            print(f"    Record ID {item_id_to_query} not found in Node {node_id}.")
            # If not found in one node, is that an error or expected? Assume error for now.
            # If it's okay for some nodes not to have it, adjust logic.
            return jsonify({"error": f"Item ID {item_id_to_query} not found in inventory {node_id}"}), 404

    if not found_record_str:
        print(f"--- Query Failed: Item ID {item_id_to_query} not found in any inventory ---")
        return jsonify({"error": f"Item ID {item_id_to_query} not found"}), 404

    if not consistent_record: # Should have been caught earlier, but double-check
         return jsonify({"error": "Inconsistent data found"}), 500

    print(f"--- Found consistent record: {found_record_str} ---")

    # 2. Aggregate Signatures
    try:
        aggregated_sigma = harn_aggregate_signatures(partial_signatures, n_pkg)
        print(f"Aggregated Signature: {aggregated_sigma}")
    except Exception as e:
        print(f"ERROR: Aggregation failed: {e}")
        return jsonify({"error": f"Signature aggregation failed: {e}"}), 500

    # 3. Encrypt Response using Procurement Officer's Public Key
    if not OFFICER_PUBLIC_KEY:
        return jsonify({"error": "Procurement Officer keys not initialized"}), 500

    try:
        encrypted_record = rsa_encrypt(found_record_str, OFFICER_PUBLIC_KEY)
        print(f"Encrypted Record for Officer: {encrypted_record}")
    except Exception as e:
        print(f"ERROR: Encryption failed: {e}")
        return jsonify({"error": f"Encryption failed: {e}"}), 500

    # 4. Return Encrypted Data and Signature Info
    return jsonify({
        "encrypted_record": str(encrypted_record), # Convert large int for JSON
        "aggregated_signature": str(aggregated_sigma), # Convert large int for JSON
        "identities": signer_ids_int,
        "random_values": signer_random_vals,
        "e_pkg": e_pkg,
        "n_pkg": n_pkg
    }), 200


@app.route('/decrypt_verify', methods=['POST'])
def decrypt_verify():
    """Handles decrypting the response and verifying the multi-signature."""
    data = request.get_json()
    if not data: # Check if JSON payload exists at all
         return jsonify({"error": "Missing JSON request body"}), 400

    print(f"\n--- Decrypting and Verifying Response ---")
    print(f"Received data: {data}") # Log received data for debugging

    # --- Input Validation ---
    required_keys = [
        'encrypted_data', 'aggregated_signature', 'identities',
        'random_values', 'e_pkg', 'n_pkg'
    ]
    processed_data = {}
    errors = {}

    for key in required_keys:
        value = data.get(key)
        if value is None: # Check if key exists and value is not None
            errors[key] = "Missing required field"
        else:
            # Try converting numeric fields, validate list types
            if key in ['encrypted_data', 'aggregated_signature', 'e_pkg', 'n_pkg']:
                try:
                    processed_data[key] = int(value)
                except (ValueError, TypeError):
                    errors[key] = f"Invalid value: Must be convertible to an integer (got '{value}')"
            elif key in ['identities', 'random_values']:
                 if not isinstance(value, list):
                      errors[key] = f"Invalid type: Must be a list (got {type(value).__name__})"
                 else:
                      # Optional: Add deeper validation (e.g., check if list elements are ints)
                      processed_data[key] = value
            else:
                 processed_data[key] = value # Should not happen with current keys

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

    # 1. Decrypt using Officer's Private Key
    if not OFFICER_PRIVATE_KEY:
        print("ERROR: Officer private key not initialized.")
        return jsonify({"error": "Procurement Officer keys not initialized"}), 500

    try:
        decrypted_message = rsa_decrypt(encrypted_data, OFFICER_PRIVATE_KEY)
        # Strip potential null bytes from conversion if necessary
        decrypted_message = decrypted_message.replace('\x00', '').strip()
        print(f"Decrypted Message: {decrypted_message}")
    except Exception as e:
        print(f"ERROR: Decryption failed: {e}")
        # It's possible decryption yields non-utf8 if something went wrong
        # or if the int->bytes conversion needs refinement.
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
        # Ensure the message used for verification matches the one signed
        is_verified = harn_verify_multi_sig(
            decrypted_message, # Use the stripped message
            aggregated_signature,
            identities,
            random_values,
            pkg_public_params
        )
        verification_status = "Verified Successfully" if is_verified else "Verification FAILED"
        print(f"Multi-Signature Verification Result: {verification_status}")
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




# --- Main Execution ---
if __name__ == '__main__':
    initialize_keys() # Generate keys when the app starts
    # Check if essential keys were generated
    if not RSA_PUBLIC_KEYS or not PKG_PUBLIC_PARAMS or not OFFICER_PUBLIC_KEY:
         print("\nCRITICAL ERROR: Essential keys failed to initialize. Exiting.")
         exit(1)
    print("\nStarting Flask server...")
    app.run(debug=True, port=5001) # Use a specific port like 5001
