import socket
import threading
import pickle
import hashlib
import secrets
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from Merkle3 import MerkleForest  # Import our MerkleForest implementation

SERVER_PORT = 8000


class GroundStation:
    def __init__(self):
        self.id = f"gs-{secrets.token_hex(8)}"
        self.registered_users = {}  # {ps_id_u: {public_key, token}}
        self.registered_drones = {}  # {ps_id_dr: {challenge, response, public_key}}
        self.drone_user_links = {}  # {drone_id: user_token}
        self.session_keys = {}  # {entity_id: session_key}

        self.skey_gs, self.pkey_gs = self.generate_key_pair()

        # Initialize Merkle Forest for drone authentication
        self.merkle_forest = MerkleForest()
        # Track which drones need updated proofs
        self.drones_needing_updates = set()
        # Map drone pseudo-identity to real ID
        self.drone_pseudo_to_real = {}

        print(f"Ground Station created with ID: {self.id}")

    def generate_key_pair(self):
        """Generate ECC key pair for ground station"""
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    def get_public_key(self):
        """Return serialized public key"""
        return self.pkey_gs.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def process_user_registration(self, ps_id_u, pkey_bytes):
        """Process a user registration request (Phase 1)"""
        print(f"Processing user registration for {ps_id_u}")
        if ps_id_u in self.registered_users:
            return {"status": "error", "message": "User already registered"}

        pkey_u = serialization.load_pem_public_key(pkey_bytes)

        tk_u = secrets.token_hex(32)

        self.registered_users[ps_id_u] = {  # Store user data
            "public_key": pkey_u,
            "token": tk_u,
            "registration_time": time.time()
        }

        print(f"User {ps_id_u} successfully registered")
        return {"status": "success", "token": tk_u}

    def process_drone_registration(self, ps_id_dr, ch_dr, res_dr, pkey_bytes):
        """Process a drone registration request (Phase 1)"""
        print(f"Processing drone registration for {ps_id_dr}")
        if ps_id_dr in self.registered_drones:
            return {"status": "error", "message": "Drone already registered"}

        pkey_dr = serialization.load_pem_public_key(pkey_bytes)  # Deserialize public key

        # Store drone information
        self.registered_drones[ps_id_dr] = {
            "challenge": ch_dr,
            "response": res_dr,
            "public_key": pkey_dr,
            "registration_time": time.time()
        }

        print(f"Data received by ground station from drone: {ps_id_dr}")

        # Add to Merkle Forest
        print("drone hash calculation")
        drone_hash = hashlib.sha256(ps_id_dr.encode()).digest()
        print("adding drone")
        tree_id, leaf_pos = self.merkle_forest.add_drone(ps_id_dr, drone_hash)
        print("added drone successfully")

        if tree_id == -1 or leaf_pos == -1:
            return {"status": "error", "message": "Failed to add drone to Merkle Forest"}

        # Generate Merkle proof for the drone
        print("start of calculation of merkle proof")
        merkle_proof = self.merkle_forest.generate_merkle_proof(ps_id_dr)
        print(merkle_proof)

        # Get root hashes for all trees in the forest
        print("start of calculation of root hash")
        root_hashes = self.merkle_forest.get_root_hashes_hex()
        print(root_hashes)

        # Check if any other drones in the same tree are affected by this addition
        # and need updated proofs
        print("calculation of tree_id")
        tree_id = self.merkle_forest.get_tree_id_for_drone(ps_id_dr)
        print("treeid -> ", tree_id)
        # if tree_id is not None:
        #     affected_drones = self.merkle_forest.get_affected_drones_by_tree(tree_id)
        #     # Remove the current drone from affected drones
        #     if ps_id_dr in affected_drones:
        #         affected_drones.remove(ps_id_dr)
        #
        #     # Add affected drones to the update queue
        #     self.drones_needing_updates.update(affected_drones)

        print(f"Drone {ps_id_dr} successfully registered with tree_id {tree_id}, leaf_pos {leaf_pos}")
        return {
            "status": "success",
            "tree_id": tree_id,
            "merkle_proof": merkle_proof,
            "root_hashes": root_hashes
        }

    def link_drone_to_user(self, drone_id, user_token):
        """Link a drone to a user using the user's token (Phase 1)"""
        print(f"Linking drone {drone_id} to user with token {user_token[:10]}...")
        token_exists = False
        for user_info in self.registered_users.values():
            if user_info["token"] == user_token:
                token_exists = True
                break

        if not token_exists:
            return {"status": "error", "message": "Invalid user token"}

        self.drone_user_links[drone_id] = user_token

        combined = drone_id.encode() + user_token.encode()
        tk_dr = hashlib.sha256(combined).digest()

        print(f"Drone {drone_id} successfully linked to user")
        return {"status": "success", "token": tk_dr}

    def authenticate_user(self, m1, ps_id_u, ts1):
        """Authenticate a user (Phase 3)"""
        print(f"Authenticating user {ps_id_u}")
        ts2 = int(time.time())

        if ps_id_u not in self.registered_users:
            return {"status": "error", "message": "User not registered"}

        if ts2 - ts1 > 300:
            return {"status": "error", "message": "Authentication timeout"}

        ts3 = int(time.time())

        unique_id = f"session-{ps_id_u}-{self.id}-{ts3}"
        sk = hashlib.sha256(unique_id.encode() +
                            hashlib.sha256(self.skey_gs.private_numbers().private_value.to_bytes(32, 'big')).digest() +
                            str(ts3).encode()).hexdigest()

        self.session_keys[ps_id_u] = sk

        print(f"User {ps_id_u} successfully authenticated")
        return {
            "status": "success",
            "session_key": sk,
            "timestamp": ts3,
            "expiry": ts3 + 3600
        }

    def initiate_drone_authentication(self, m1, ps_id_dr, ts1):
        """Initiate drone authentication (Phase 4)"""
        print(f"Initiating authentication for drone {ps_id_dr}")
        ts2 = int(time.time())

        if ps_id_dr not in self.registered_drones:
            return {"status": "error", "message": "Drone not registered"}

        if ts2 - ts1 > 300:
            return {"status": "error", "message": "Authentication timeout"}

        ch_dr_new = secrets.token_bytes(32)
        ch_dr = self.registered_drones[ps_id_dr]["challenge"]

        ts3 = int(time.time())

        print(f"Sending challenge to drone {ps_id_dr}")
        response = {
            "status": "success",
            "challenge": ch_dr,
            "new_challenge": ch_dr_new,
            "timestamp": ts3
        }

        return response

    def verify_drone_response(self, m3, ch_dr, new_res_dr, res_dr, ts5, ps_id_dr):
        """Verify drone response to challenge (Phase 4)"""
        print(f"Verifying response from drone {ps_id_dr}")
        ts6 = int(time.time())

        if ps_id_dr not in self.registered_drones:
            return {"status": "error", "message": "Drone not registered"}

        if ts6 - ts5 > 300:
            return {"status": "error", "message": "Authentication timeout"}

        stored_res = self.registered_drones[ps_id_dr]["response"]

        if res_dr != stored_res:
            return {"status": "error", "message": "Invalid PUF response"}

        ts7 = int(time.time())
        sk = hashlib.sha256(f"{ps_id_dr}{ts7}{self.id}".encode()).hexdigest()

        self.session_keys[ps_id_dr] = sk

        self.registered_drones[ps_id_dr]["challenge"] = ch_dr
        self.registered_drones[ps_id_dr]["response"] = new_res_dr

        updated_proof = self.merkle_forest.generate_merkle_proof(ps_id_dr)
        updated_root_hashes = self.merkle_forest.get_root_hashes_hex()

        print(f"Drone {ps_id_dr} successfully authenticated")
        return {
            "status": "success",
            "session_key": sk,
            "timestamp": ts7,
            "expiry": ts7 + 3600,
            "merkle_proof": updated_proof,
            "root_hashes": updated_root_hashes
        }

    def get_merkle_proof(self, ps_id_dr):
        """Get the current Merkle proof for a drone"""
        if ps_id_dr not in self.registered_drones:
            return {"status": "error", "message": "Drone not registered"}

        # Generate Merkle proof
        merkle_proof = self.merkle_forest.generate_merkle_proof(ps_id_dr)
        if not merkle_proof.get("success", False):
            return {"status": "error", "message": "Failed to generate Merkle proof"}

        # Get root hashes
        root_hashes = self.merkle_forest.get_root_hashes_hex()

        return {
            "status": "success",
            "merkle_proof": merkle_proof,
            "root_hashes": root_hashes
        }

    def get_root_hashes(self):
        """Get the current root hashes for all trees in the forest"""
        root_hashes = self.merkle_forest.get_root_hashes_hex()
        return {
            "status": "success",
            "root_hashes": root_hashes
        }


class GroundStationServer:
    def __init__(self, host='0.0.0.0', port=SERVER_PORT):
        self.host = host
        self.port = port
        self.ground_station = GroundStation()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        """Start the ground station server"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        print(f"Ground Station Server started on {self.host}:{self.port}")
        print(f"Ground Station ID: {self.ground_station.id}")

        try:
            while True:
                client_socket, address = self.server_socket.accept()
                print(f"Connection from {address}")
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_handler.daemon = True
                client_handler.start()
        except KeyboardInterrupt:
            print("Server shutting down...")
        finally:
            self.server_socket.close()

    def handle_client(self, client_socket, address):
        """Handle client connections"""
        try:
            while True:
                # Receive data length (4 bytes)
                data_len_bytes = client_socket.recv(4)
                if not data_len_bytes:
                    break

                data_len = int.from_bytes(data_len_bytes, byteorder='big')

                # Receive data based on the length
                data = b''
                while len(data) < data_len:
                    packet = client_socket.recv(data_len - len(data))
                    if not packet:
                        break
                    data += packet

                if not data:
                    print(f"Client {address} disconnected")
                    break

                request = pickle.loads(data)
                print(f"Received request: {request['action']} from {address}")

                response = self.process_request(request)

                # Serialize and send the response
                response_data = pickle.dumps(response)
                response_len = len(response_data).to_bytes(4, byteorder='big')
                client_socket.sendall(response_len + response_data)

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()

    def process_request(self, request):
        """Process client requests based on action"""
        action = request.get('action')
        if action == 'register_user':
            return self.ground_station.process_user_registration(
                request['ps_id_u'],
                request['pkey_bytes']
            )
        elif action == 'register_drone':
            # drone_id = request.get('drone_id')  # This may be None
            return self.ground_station.process_drone_registration(
                request['ps_id_dr'],
                request['ch_dr'],
                request['res_dr'],
                request['pkey_bytes'],
                # drone_id
            )
        elif action == 'link_drone_to_user':
            return self.ground_station.link_drone_to_user(
                request['drone_id'],
                request['user_token']
            )
        elif action == 'authenticate_user':
            return self.ground_station.authenticate_user(
                request['m1'],
                request['ps_id_u'],
                request['ts1']
            )
        elif action == 'initiate_drone_authentication':
            return self.ground_station.initiate_drone_authentication(
                request['m1'],
                request['ps_id_dr'],
                request['ts1']
            )
        elif action == 'verify_drone_response':
            return self.ground_station.verify_drone_response(
                request['m3'],
                request['ch_dr'],
                request['new_res_dr'],
                request['res_dr'],
                request['ts5'],
                request['ps_id_dr']
            )
        elif action == 'get_public_key':
            return {
                'status': 'success',
                'public_key': self.ground_station.get_public_key()
            }
        elif action == 'get_ground_station_id':
            return {
                'status': 'success',
                'id': self.ground_station.id
            }
        elif action == 'get_merkle_proof':
            return self.ground_station.get_merkle_proof(
                request['ps_id_dr']
            )
        elif action == 'get_root_hashes':
            return self.ground_station.get_root_hashes()
        elif action == 'receive_message':
            return {
                'status': 'success',
            }
        else:
            return {'status': 'error', 'message': f'Unknown action: {action}'}


if __name__ == "__main__":
    server = GroundStationServer()
    server.start()
