import hashlib
import math

def extended_gcd(a, b):
    """Computes the extended Euclidean algorithm."""
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y

def modInverse(a, m):
    """Computes the modular inverse of a modulo m."""
    d, x, y = extended_gcd(a, m)
    if d != 1:
        # Inverse does not exist
        # This should not happen with the provided keys if e is chosen correctly
        raise ValueError("Modular inverse does not exist")
    else:
        return x % m

def message_to_int(message):
    """Converts a string message to an integer."""
    return int.from_bytes(message.encode("utf-8"), "big")

def int_to_message(integer, byte_len=None):
    """Converts an integer back to a string message."""
    if byte_len is None:
        # Estimate length, might need adjustment if leading zeros are critical
        byte_len = (integer.bit_length() + 7) // 8
    try:
        return integer.to_bytes(byte_len, "big").decode("utf-8")
    except UnicodeDecodeError:
        print(f"Warning: Potential decoding issue for int {integer}")
        # Attempt recovery, might be lossy
        return integer.to_bytes((integer.bit_length() + 7) // 8, "big").decode(
            "utf-8", errors="ignore"
        )
    except OverflowError:
        print(f"Error: Integer {integer} too large to convert to bytes.")
        return f"Error: Decryption resulted in integer too large ({integer})"


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


#RSA Functions

def generate_rsa_keys(p, q, e):
    """Generates RSA public and private keys from p, q, e."""
    n = p * q
    phi_n = (p - 1) * (q - 1)
    d = modInverse(e, phi_n)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def rsa_sign(message, private_key):
    """Signs a message using RSA private key."""
    d, n = private_key
    msg_hash_int = hash_message_to_int(message)
    # Ensure hash is smaller than n
    if msg_hash_int >= n:
        raise ValueError("Hash is larger than modulus n")
    signature = pow(msg_hash_int, d, n)
    return signature

def rsa_verify(message, signature, public_key):
    """Verifies an RSA signature using the public key."""
    e, n = public_key
    msg_hash_int = hash_message_to_int(message)
    if msg_hash_int >= n:
        # If hash was too large during signing, fails
        print("Warning: Hash is larger than modulus n during verification")
    decrypted_hash_int = pow(signature, e, n)
    return decrypted_hash_int == msg_hash_int

def rsa_encrypt(message_str, public_key):
    """Encrypts a string message using RSA public key.
    If message is too large, splits it into chunks."""
    e, n = public_key
    
    # Calculate maximum bytes that can be encrypted with this key
    max_bytes = (n.bit_length() - 1) // 8
    
    # If message fits in one block, encrypt normally
    msg_bytes = message_str.encode("utf-8")
    if len(msg_bytes) <= max_bytes - 11:  # Reserve space for PKCS#1 padding
        msg_int = message_to_int(message_str)
        if msg_int >= n:
            raise ValueError(
                f"Message integer representation ({msg_int}) is larger than modulus n ({n})"
            )
        return pow(msg_int, e, n)
    
    # For larger messages, encrypt in chunks and combine with a delimiter
    chunks = []
    chunk_size = max_bytes - 11  # Safe size accounting for padding
    
    # Split message into chunks
    for i in range(0, len(msg_bytes), chunk_size):
        chunk = msg_bytes[i:i+chunk_size].decode('utf-8', errors='ignore')
        chunk_int = message_to_int(chunk)
        encrypted_chunk = pow(chunk_int, e, n)
        chunks.append(str(encrypted_chunk))
    
    # Return a special format indicating chunked encryption
    return "CHUNKED:" + "|".join(chunks)

def rsa_decrypt(ciphertext, private_key):
    """Decrypts a ciphertext using RSA private key.
    Handles both single blocks and chunked messages."""
    d, n = private_key
    
    # Check if this is a chunked ciphertext
    if isinstance(ciphertext, str) and ciphertext.startswith("CHUNKED:"):
        chunks = ciphertext[8:].split("|")  # Remove "CHUNKED:" prefix and split
        decrypted_chunks = []
        
        for chunk in chunks:
            chunk_int = int(chunk)
            decrypted_int = pow(chunk_int, d, n)
            byte_len = (n.bit_length() + 7) // 8
            decrypted_text = int_to_message(decrypted_int, byte_len)
            decrypted_chunks.append(decrypted_text)
        
        # Combine all chunks
        return "".join(decrypted_chunks)
    
    # Regular single-block decryption
    decrypted_int = pow(ciphertext, d, n)
    byte_len = (n.bit_length() + 7) // 8  # max
    return int_to_message(decrypted_int, byte_len)


# --- Harn Identity-Based Multi-Signature Functions ---
# masterkey (p, q, e_pkg). n_pkg = p*q.
# user secret key s_i = ID_i ^ d_pkg mod n_pkg.
# partial sig sigma_i = H(m || r_i) ^ s_i mod n_pkg.
# aggregate sig sigma = product(sigma_i) mod n_pkg.
# verification: sigma ^ e_pkg == product(H(m || r_i) ^ ID_i) mod n_pkg 

def harn_pkg_setup(p, q, e):
    """Generates PKG public parameters and master secret key."""
    n_pkg = p * q
    phi_n = (p - 1) * (q - 1)
    try:
        d_pkg = modInverse(e, phi_n)
    except ValueError:
         raise ValueError("PKG 'e' is not invertible modulo phi(n). Check PKG p, q, e.")
    pkg_public_params = (e, n_pkg)  # (e_pkg, n_pkg)
    pkg_master_secret = d_pkg
    return pkg_public_params, pkg_master_secret

def harn_extract_secret_key(identity_int, pkg_master_secret, n_pkg):
    """Computes the user's secret key s_i based on their identity."""
    # s_i = identity_int * d_pkg (so that s_i * e_pkg ≡ identity_int mod φ(n))
    user_secret_key = identity_int * pkg_master_secret
    return user_secret_key

def harn_hash_msg_rand(message, random_val, n_pkg=None):
    """Hashes the message concatenated with the random value using full SHA-256."""
    combined = f"{message}||{random_val}"
    # Use the full hash rather than reducing modulo n_pkg to avoid hash collisions
    return hash_message_to_int(combined)

def harn_partial_sign(message, random_val, user_secret_key, n_pkg):
    """Generates a partial signature for the message."""
    # sigma_i = H(m || r_i) ^ s_i mod n_pkg
    h_mr = harn_hash_msg_rand(message, random_val, n_pkg)
    partial_signature = pow(h_mr, user_secret_key, n_pkg)
    return partial_signature

def harn_aggregate_signatures(partial_signatures, n_pkg):
    """Aggregates partial signatures by multiplication."""
    # sigma = product(sigma_i) mod n_pkg
    aggregated_sigma = 1
    for sig in partial_signatures:
        aggregated_sigma = (aggregated_sigma * sig) % n_pkg
    return aggregated_sigma

def harn_verify_multi_sig(
    message,
    aggregated_sigma,
    identities, 
    random_values,
    pkg_public_params,
):
    """Verifies the aggregated multi-signature."""
    e_pkg, n_pkg = pkg_public_params
    
    # Ensure all parameters are integers
    if isinstance(aggregated_sigma, str):
        aggregated_sigma = int(aggregated_sigma)
    if isinstance(e_pkg, str):
        e_pkg = int(e_pkg)
    if isinstance(n_pkg, str):
        n_pkg = int(n_pkg)

    print(f"Verification using: e_pkg={e_pkg}, n_pkg={n_pkg}")
    # Compute left side: sigma^e_pkg mod n_pkg
    left_side = pow(aggregated_sigma, e_pkg, n_pkg)
    print(f"Left side (sigma^e): {left_side}")

    # Compute right side: product(H(m||r_i) ^ identity_int mod n_pkg)
    right_side = 1
    if len(identities) != len(random_values):
        raise ValueError("Number of identities and random values must match.")

    for i in range(len(identities)):
        identity_int = identities[i]
        random_val = random_values[i]
        h_mr = harn_hash_msg_rand(message, random_val, n_pkg)
        # Correct: raise hash to the identity power
        term = pow(h_mr, identity_int, n_pkg)
        right_side = (right_side * term) % n_pkg
        print(f"  Term {i+1}: identity={identity_int}, random={random_val}, h_mr={h_mr}, term={term}")

    print(f"Right side: {right_side}")
    return left_side == right_side


