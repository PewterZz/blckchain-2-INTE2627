# Blockchain Inventory System

A secure distributed inventory system with cryptographic features including RSA digital signatures, consensus protocol, and multi-signature verification.

## Setup and Installation

1. Clone this repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Run the application:
   ```
   python app.py
   ```
   The server will start on http://localhost:5001

## Key Features

- RSA digital signatures for inventory record authenticity
- Proof-of-Authority consensus protocol (threshold: 3/4 nodes)
- Harn identity-based multi-signature verification
- Encrypted delivery of query responses
- Replay attack protection with timestamps
- Tabbed user interface separating Part 1 and Part 2 functionality
- Improved feedback with status messages and color-coded responses

## System Architecture

The system consists of two main parts as required by the assignment specifications:

### Part 1: Digital Signatures & Consensus
- User can add new inventory records through the UI
- RSA signature generation for records using inventory node's private key
- Consensus protocol ensures at least 3 out of 4 nodes agree before committing
- Records are stored in all inventory databases upon successful consensus

### Part 2: Multi-Signature & Secure Query
- User can query records by Item ID
- Query triggers a multi-signature process using the Harn identity-based scheme
- All node signatures are aggregated into a single signature
- Response is encrypted with the procurement officer's public key
- Officer can decrypt and verify the response

## API Endpoints

### 1. Add Inventory Record

```bash
curl -X POST http://localhost:5001/add_record \
  -H "Content-Type: application/json" \
  -d '{
    "signer": "A",
    "item_id": "003",
    "qty": 50,
    "price": 23,
    "location": "A"
  }'
```

### 2. Query Item

```bash
curl -X POST http://localhost:5001/query_item \
  -H "Content-Type: application/json" \
  -d '{
    "query_item_id": "003"
  }'
```

### 3. Decrypt and Verify Response

The response from the query endpoint contains encrypted data and signature information. To decrypt and verify:

```bash
curl -X POST http://localhost:5001/decrypt_verify \
  -H "Content-Type: application/json" \
  -d '{
    "encrypted_data": "<encrypted_data_from_query>",
    "aggregated_signature": "<aggregated_signature_from_query>",
    "identities": [126, 127, 128, 129],
    "random_values": [621, 721, 821, 921],
    "e_pkg": "<e_pkg_from_query>",
    "n_pkg": "<n_pkg_from_query>",
    "signed_message": "<signed_message_from_query>"
  }'
```

## Testing

The system architecture ensures:
1. Only valid signed records are added
2. Consensus is required before committing records 
3. Queries return multi-signed, encrypted responses
4. Officer can decrypt and verify multi-signatures

## Consensus Protocol Justification

The system implements a Proof-of-Authority (PoA) consensus mechanism with a threshold of 3/4 nodes. This protocol was chosen because:

1. **Known Participants**: All inventory nodes are known and trusted entities
2. **No Sybil Risk**: The permissioned network prevents identity spoofing attacks
3. **Low Latency**: PoA provides fast transaction finality without costly computations
4. **Energy Efficiency**: No resource-intensive mining required
5. **Small Network**: With only 4 nodes, PBFT-like majority voting is simple and effective

## Assignment Notes

Based on discussions with teaching staff, the following clarifications apply to this implementation:

- Part 1 and Part 2 are separate functionalities but use the same database files
- All cryptographic calculations are shown in the frontend as required
- The record location (A/B/C/D) affects the consensus process
- Consensus validation occurs across all inventory nodes
- During demonstrations, markers will test with custom records
- The report should document both Part 1 and Part 2 functionality
- For multi-signature verification testing, database files can be directly modified 