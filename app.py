"""
Anansiflo API: A Flask mock backend for blockchain wallet authorization.
- Use as-is for testing (mocked by default: USE_MOCK_BLOCKCHAIN=True).
- Set USE_MOCK_BLOCKCHAIN=False and add .env for real Ethereum calls.
- Default API keys: admin123 (admin), user456 (user).
- Endpoints: /health, /api/auth (POST with X-API-Key header).
- Requires: flask, python-dotenv, web3, flask-limiter.
"""
from flask import Flask, jsonify, request
from dotenv import load_dotenv
import os
import logging
import hashlib
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import unittest
import json

# Load environment variables
load_dotenv()

# Logging setup
logging.basicConfig(
    filename="api_requests.log",
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s", "ip": "%(ip)s", "api_key": "%(api_key)s", "endpoint": "%(endpoint)s", "data": "%(data)s"}'
)

app = Flask(__name__)

# Blockchain setup (mocked by default)
USE_MOCK_BLOCKCHAIN = os.getenv("USE_MOCK_BLOCKCHAIN", "True").lower() == "true"

if not USE_MOCK_BLOCKCHAIN:
    from web3 import Web3, Account
    INFURA_URL = os.getenv("INFURA_URL")
    web3 = Web3(Web3.HTTPProvider(INFURA_URL))
    try:
        if not web3.is_connected():
            raise ValueError("Failed to connect to Ethereum node.")

        CONTRACT_ADDRESS = web3.to_checksum_address(os.getenv("CONTRACT_ADDRESS"))
        SENDER_ADDRESS = web3.to_checksum_address(os.getenv("SENDER_ADDRESS"))
        SENDER_PRIVATE_KEY = os.getenv("SENDER_PRIVATE_KEY")
        if not SENDER_PRIVATE_KEY:
            raise ValueError("SENDER_PRIVATE_KEY is missing.")
    except ValueError as e:
        logging.error(f"Error setting up blockchain (ValueError): {e}")
        raise
    except Exception as e:
        logging.error(f"Error setting up blockchain: {e}")
        raise

    CONTRACT_ABI = [
        {
            "constant": True,
            "inputs": [{"name": "_user", "type": "address"}],
            "name": "isAuthorized",
            "outputs": [{"name": "", "type": "bool"}],
            "type": "function"
        },
        {
            "constant": False,
            "inputs": [{"name": "_user", "type": "address"}],
            "name": "logFraud",
            "outputs": [],
            "type": "function"
        }
    ]
    contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
else:
    # Mock blockchain setup
    logging.warning("Using MOCK Blockchain setup")
    web3 = None
    CONTRACT_ABI = []
    contract = None
    SENDER_ADDRESS = "0xMockSenderAddress"
    SENDER_PRIVATE_KEY = "MockPrivateKey"

# Security setup with hashed API keys and roles
API_KEYS = {
    "admin": hashlib.sha256(os.getenv("ADMIN_API_KEY", "admin123").encode()).hexdigest(),
    "user1": hashlib.sha256(os.getenv("USER1_API_KEY", "user456").encode()).hexdigest()
}
ROLES = {
    "admin": "admin",
    "user1": "user"
}
ALLOWED_IPS = os.getenv("ALLOWED_IPS", "127.0.0.1").split(",")

# Rate limiting by API key
def get_api_key():
    return request.headers.get("X-API-Key", "default")

limiter = Limiter(get_api_key, app=app, default_limits=["10 per minute"])

class RequestFormatter(logging.Formatter):
    def format(self, record):
        record.ip = request.remote_addr if request else "N/A"
        record.api_key = request.headers.get("X-API-Key", "N/A") if request else "N/A"
        record.endpoint = request.path if request else "N/A"
        record.data = request.get_json(silent=True) if request else "N/A"
        return super().format(record)

formatter = RequestFormatter(
    '{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s", "ip": "%(ip)s", "api_key": "%(api_key)s", "endpoint": "%(endpoint)s", "data": "%(data)s"}'
)
for handler in logging.getLogger().handlers:
    handler.setFormatter(formatter)

# Helper function to send signed transactions
def send_transaction(function, **kwargs):
    if not USE_MOCK_BLOCKCHAIN:
        tx = function.build_transaction({
            "from": SENDER_ADDRESS,
            "gas": 200000,
            "gasPrice": web3.eth.gas_price,
            "nonce": web3.eth.get_transaction_count(SENDER_ADDRESS)
        })
        signed_tx = Account.sign_transaction(tx, SENDER_PRIVATE_KEY)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        return tx_hash
    else:
        logging.warning("Mock: Sending a transaction")
        return bytes.fromhex("1234567890")  # Simplified mock hash

# API Route: Verify Blockchain Access with role-based access
@app.route("/api/auth", methods=["POST"])
@limiter.limit("5 per minute")
def check_access():
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return jsonify({"error": "Missing API Key"}), 401

    hashed_api_key = hashlib.sha256(api_key.encode()).hexdigest()
    user_role = None
    for user, hashed_key in API_KEYS.items():
        if hashed_key == hashed_api_key:
            user_role = ROLES.get(user)
            break

    if not user_role:
        return jsonify({"error": "Invalid API Key"}), 403

    # if user_role != "admin":
    #     return jsonify({"error": "Insufficient permissions"}), 403

    data = request.json
    if not data or "wallet_address" not in data:
        return jsonify({"error": "Missing wallet_address"}), 400

    user_address = data.get("wallet_address")
    if not USE_MOCK_BLOCKCHAIN and not web3.is_address(user_address):
        return jsonify({"error": "Invalid Ethereum address"}), 400
    if not USE_MOCK_BLOCKCHAIN:
        user_address = web3.to_checksum_address(user_address)

    is_authorized = False
    if not USE_MOCK_BLOCKCHAIN:
        try:
            is_authorized = contract.functions.isAuthorized(user_address).call()
        except Exception as e:
            logging.error(f"Blockchain call failed: {e}")
            return jsonify({"error": "Failed to check authorization", "details": str(e)}), 500
    else:
        # Mock behavior: authorized only for a specific test address
        is_authorized = user_address == "0x1234567890123456789012345678901234567890" or user_role == "admin"

    if is_authorized:
        logging.info(f"Authorized access for {user_address}")
        return jsonify({"message": "Access Granted", "status": "authorized"}), 200
    else:
        logging.warning(f"Unauthorized access attempt for {user_address}")
        fraud_tx = None
        if "logFraud" in [f["name"] for f in CONTRACT_ABI] and not USE_MOCK_BLOCKCHAIN:
            try:
                tx_hash = send_transaction(contract.functions.logFraud(user_address))
                receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                if receipt.status == 1:
                    fraud_tx = tx_hash.hex()
                    logging.info(f"Fraud logged successfully: {fraud_tx}")
                else:
                    logging.error(f"Fraud logging transaction failed: {tx_hash.hex()}")
            except Exception as e:
                logging.error(f"Fraud logging failed: {e}")
        elif USE_MOCK_BLOCKCHAIN:
            fraud_tx = "0xMockFraudTxHash"
        return jsonify({"message": "Access Denied", "status": "unauthorized", "fraud_tx": fraud_tx}), 403

# Health Check Route
@app.route("/health", methods=["GET"])
def health_check():
    if not USE_MOCK_BLOCKCHAIN:
        return jsonify({"status": "healthy", "blockchain_connected": web3.is_connected()}), 200
    else:
        return jsonify({"status": "healthy", "blockchain_connected": True}), 200

class APITestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        self.admin_key = os.getenv("ADMIN_API_KEY", "admin123")
        self.admin_key_hashed = hashlib.sha256(self.admin_key.encode()).hexdigest()
        self.user1_key = os.getenv("USER1_API_KEY", "user456")

    def test_health_check(self):
        response = self.app.get('/health')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'healthy')

    def test_missing_api_key(self):
        response = self.app.post('/api/auth', json={"wallet_address": "0xValidAddress"})
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertEqual(data['error'], 'Missing API Key')

    def test_invalid_api_key(self):
        response = self.app.post('/api/auth', headers={"X-API-Key": "invalidkey"}, json={"wallet_address": "0xValidAddress"})
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.data)
        self.assertEqual(data['error'], 'Invalid API Key')

    # def test_invalid_permission(self):
    #     response = self.app.post('/api/auth', headers={"X-API-Key": self.user1_key}, json={"wallet_address": "0xValidAddress"})
    #     self.assertEqual(response.status_code, 403)
    #     data = json.loads(response.data)
    #     self.assertEqual(data['error'], 'Insufficient permissions')
    
    def test_check_access_success(self):
        response = self.app.post('/api/auth', headers={"X-API-Key": self.admin_key}, json={"wallet_address": "0x1234567890123456789012345678901234567890"})
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Access Granted')

    def test_invalid_wallet_address(self):
        response = self.app.post('/api/auth', headers={"X-API-Key": self.admin_key}, json={"wallet_address": "invalid"})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertEqual(data['error'], 'Invalid Ethereum address')

    def test_fraud_logging(self):
        response = self.app.post('/api/auth', headers={"X-API-Key": self.admin_key}, json={"wallet_address": "0x583031D1113aD414F02576BD6afaBfb302140225"})
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Access Denied')
        self.assertEqual(data['status'], 'unauthorized')
        if USE_MOCK_BLOCKCHAIN:
            self.assertEqual(data['fraud_tx'], "0xMockFraudTxHash")

    def test_check_access_success_admin_mock(self):
        response = self.app.post('/api/auth', headers={"X-API-Key": self.admin_key}, json={"wallet_address": "0x583031D1113aD414F02576BD6afaBfb302140225"})
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Access Granted')

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
    unittest.main(argv=['first-arg-is-ignored'], exit=False, failfast=True)
