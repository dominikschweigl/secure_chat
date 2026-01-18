import json
from datetime import datetime, timezone
from Crypto.Hash import SHA256, HMAC

def _generate_request_signature(session_key: str, request_body: str, timestamp: str) -> str:
    """
    Generate HMAC-SHA256 signature for a request.
    
    Args:
        session_key: The session key (acts as signing key)
        request_body: JSON string of request body or empty string for GET
        timestamp: ISO format timestamp
        
    Returns:
        str: Hex-encoded HMAC-SHA256 signature
    """
    message = f"{request_body}|{timestamp}".encode('utf-8')
    hmac = HMAC.new(session_key.encode('utf-8'), digestmod=SHA256)
    hmac.update(message)
    return hmac.hexdigest()

def get_auth_headers(session_key: str, request_body: str = "") -> dict:
    """
    Generate authentication headers for a request.
    
    Args:
        session_key: The session key
        request_body: JSON string of request body (empty for GET requests)
        
    Returns:
        dict: Headers with X-Request-Signature and X-Request-Timestamp
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    signature = _generate_request_signature(session_key, request_body, timestamp)
    return {
        "X-Request-Signature": signature,
        "X-Request-Timestamp": timestamp
    }