# Part 1: Digital Signatures & Consensus
from flask import Flask, render_template, request, jsonify
import json
import os
import time
import hashlib
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from params import (
    INVENTORY_KEYS, CONSENSUS_THRESHOLD, INVENTORY_IDS
)
from crypto_utils import (
    generate_rsa_keys, rsa_sign, rsa_verify
)

app = Flask(__name__, template_folder='./templates')
DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)  # Ensure data directory exists

RSA_PUBLIC_KEYS = {}
RSA_PRIVATE_KEYS = {}

def initialize_keys():
    """Generate and store inventory RSA keys on application start."""
    global RSA_PUBLIC_KEYS, RSA_PRIVATE_KEYS

    print("Initializing cryptographic keys for Part 1...")

    # Inventory RSA Keys
    for inv_id, keys in INVENTORY_KEYS.items():
        try:
            pub, priv = generate_rsa_keys(keys['p'], keys['q'], keys['e'])
            RSA_PUBLIC_KEYS[inv_id] = pub
            RSA_PRIVATE_KEYS[inv_id] = priv
            print(f"  - Generated RSA keys for Inventory {inv_id}")
        except ValueError as e:
            print(f"Error generating RSA keys for Inventory {inv_id}: {e}")

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

def hash_message_to_int(message, n=None):
    """Hashes a message using SHA-256 and returns an integer.
    If n is provided, returns hash_int % n."""
    hasher = hashlib.sha256()
    hasher.update(message.encode("utf-8"))
    hash_bytes = hasher.digest()
    hash_int = int.from_bytes(hash_bytes, "big")
    if n:
        return hash_int % n
    return hash_int

@app.route('/')
def index():
    """Renders the main HTML page for Part 1."""
    return render_template('index.html')

@app.route('/add_record', methods=['POST'])
def add_record():
    #Handles adding a new record: RSA Sign -> Consensus -> Commit.
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
        
    # Convert values with proper error handling
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
             }), 500 
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
        }), 403  

if __name__ == "__main__":
    import socket
    import argparse
    
    initialize_keys()
    
    parser = argparse.ArgumentParser(description='Run the Blockchain Inventory System Part 1 (Digital Signatures & Consensus)')
    parser.add_argument('--port', type=int, default=5001, help='Port number to run the server on')
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
    
    print(f"\n==== Starting Blockchain Inventory System Part 1 on port {port} ====")
    print(f"Access the application at http://localhost:{port}")
    
    app.run(host='0.0.0.0', port=port, debug=args.debug)
