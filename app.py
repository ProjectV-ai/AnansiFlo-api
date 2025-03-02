from flask import Flask, jsonify, request, redirect
from dotenv import load_dotenv
from web3 import Web3, Account
import os, sys
import logging
import hashlib
from flask_limiter import Limiter
from flask_caching import Cache
from unittest.mock import patch
import unittest
import json

# Load environment variables
load_dotenv()

# Logging setup
logging.basicConfig(level=logging.INFO, format='{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}')

app = Flask(__name__)

# Blockchain setup
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

# Security setup with hashed API keys and roles
API_KEYS = {
    "admin": hashlib.sha256(os.getenv("ADMIN_API_KEY").encode()).hexdigest(),
    "user1": hashlib.sha256(os.getenv("USER1_API_KEY").encode()).hexdigest()
}
ROLES = {
    "admin": "admin",
    "user1": "user"
}
ALLOWED_IPS = os.getenv("ALLOWED_IPS", "").split(",")

# Rate limiting by API key
def get_api_key():
    return request.headers.get("X-API-Key", "default")

limiter = Limiter(get_api_key, app=app, default_limits=["10 per minute"])

# Caching setup
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache'})

# HTTPS Enforcement Middleware
@app.before_request
def enforce_https():
    if request.url.startswith('http://'):
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

@app.before_request
def log_request():
    logging.info(f"IP: {request.remote_addr} | API Key: {request.headers.get('X-API-Key')} | Endpoint: {request.path} | Data: {request.json}")

@app.before_request
def restrict_ip():
    if ALLOWED_IPS and request.remote_addr not in ALLOWED_IPS:
        return jsonify({"error": "Unauthorized IP"}), 403

# Helper function to send signed transactions
def send_transaction(function, **kwargs):
    tx = function.build_transaction({
        "from": SENDER_ADDRESS,
        "gas": 200000,
        "gasPrice": web3.eth.gas_price,
        "nonce": web3.eth.get_transaction_count(SENDER_ADDRESS)
    })
    signed_tx = Account.sign_transaction(tx, SENDER_PRIVATE_KEY)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    return tx_hash

# API Route: Verify Blockchain Access with caching and role-based access
@app.route("/api/auth", methods=["POST"])
@cache.cached(timeout=60, query_string=True)  # Cache for 60 seconds
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

    # Role-based access control: only admins can access this endpoint
    if user_role != "admin":
        return jsonify({"error": "Insufficient permissions"}), 403

    data = request.json
    if not data or "wallet_address" not in data:
        return jsonify({"error": "Missing wallet_address"}), 400

    user_address = data.get("wallet_address")
    if not web3.is_address(user_address):
        return jsonify({"error": "Invalid Ethereum address"}), 400
    user_address = web3.to_checksum_address(user_address)
    
    is_authorized = False
    try:
        is_authorized = contract.functions.isAuthorized(user_address).call()
    except Exception as e:
        logging.error(f"Blockchain call failed: {e}")
        return jsonify({"error": "Failed to check authorization", "details": str(e)}), 500

    if is_authorized:
        logging.info(f"Authorized access for {user_address}")
        return jsonify({"message": "Access Granted", "status": "authorized"}), 200
    else:
        logging.warning(f"Unauthorized access attempt for {user_address}")
        fraud_tx = None
        if "logFraud" in [f["name"] for f in CONTRACT_ABI]:
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
        return jsonify({"message": "Access Denied", "status": "unauthorized", "fraud_tx": fraud_tx}), 403

# Health Check Route
@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "blockchain_connected": web3.is_connected()}), 200

class APITestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

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

    def test_invalid_permission(self):
        response = self.app.post('/api/auth', headers={"X-API-Key": os.getenv("USER1_API_KEY")}, json={"wallet_address": "0xValidAddress"})
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.data)
        self.assertEqual(data['error'], 'Insufficient permissions')

    @patch("app.contract.functions.isAuthorized.call")
    def test_check_access_success(self, mock_is_authorized):
        mock_is_authorized.return_value = True
        response = self.app.post('/api/auth', headers={"X-API-Key": os.getenv("ADMIN_API_KEY")}, json={"wallet_address": "0xValidAddress"})
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Access Granted')

    def test_invalid_wallet_address(self):
        response = self.app.post('/api/auth', headers={"X-API-Key": os.getenv("ADMIN_API_KEY")}, json={"wallet_address": "invalid"})
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertEqual(data['error'], 'Invalid Ethereum address')

    @patch("app.web3.eth.wait_for_transaction_receipt")
    @patch("app.web3.eth.send_raw_transaction")
    @patch("app.web3.eth.get_transaction_count")
    def test_fraud_logging(self,mock_get_transaction_count, mock_send_raw_transaction, mock_wait_for_transaction_receipt):
        mock_get_transaction_count.return_value = 0
        mock_send_raw_transaction.return_value = bytes.fromhex("0x1234567890")
        mock_wait_for_transaction_receipt.return_value = {'status': 1}
        response = self.app.post('/api/auth', headers={"X-API-Key": os.getenv("ADMIN_API_KEY")}, json={"wallet_address": "0x583031D1113aD414F02576BD6afaBfb302140225"})
        self.assertEqual(response.status_code, 403)
        data = json.loads(response.data)
        self.assertEqual(data['message'], 'Access Denied')
        self.assertEqual(data['status'], 'unauthorized')
        self.assertEqual(data['fraud_tx'], "0x1234567890")

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
    if 'unittest' in sys.modules:
        unittest.main()
def setUp(self):
    self.app = app.test_client()
    self.app.testing = True
    app.config['TESTING'] = True # this allows us to test in the context of the app.
    self.admin_key = os.getenv("ADMIN_API_KEY")
    self.user1_key = os.getenv("USER1_API_KEY")
def tearDown(self):
    cache.clear()
