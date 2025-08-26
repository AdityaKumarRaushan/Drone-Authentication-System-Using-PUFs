import socket
import threading
import pickle
import hashlib
import secrets
import time
import os
import sys
import argparse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Global configuration
GS_HOST = "192.168.137.1"
GS_PORT = 8000
DRONE_PORT = 8001


class Drone:
    def __init__(self):
        self.id_dr = self.generate_drone_id()
        self.nonce = secrets.token_bytes(16)

        self.ch_dr = secrets.token_bytes(32)
        self.res_dr = self.puf_function(self.ch_dr)

        self.ps_id_dr = self.generate_pseudo_identity()
        self.skey_dr, self.pkey_dr = self.generate_key_pair()

        self.token = None
        self.tree_id = None
        self.leaf_position = None
        self.ground_station_id = None
        self.tk_dr = None
        self.session_keys = {}

        # Merkle tree related information
        self.merkle_proof = None
        self.root_hashes = None
        self.my_leaf_hash = None

        print(f"Drone created with ID: {self.id_dr}")
        print(f"Pseudo ID: {self.ps_id_dr}")

    def generate_drone_id(self):
        return f"drone-{secrets.token_hex(8)}"

    def puf_function(self, challenge):
        unique_hardware_signature = f"hw-sig-{self.id_dr}".encode()
        return hashlib.sha256(challenge + unique_hardware_signature).digest()

    def generate_pseudo_identity(self):
        combined = self.id_dr.encode() + self.nonce
        return hashlib.sha256(combined).hexdigest()

    def generate_key_pair(self):
        skey_material = hashlib.sha256(self.ch_dr + self.id_dr.encode() + self.nonce).digest()

        private_key = ec.derive_private_key(
            int.from_bytes(skey_material, 'big'),
            ec.SECP256R1()
        )
        public_key = private_key.public_key()

        return private_key, public_key

    def register_with_ground_station(self, gs_host, gs_port):
        """Register drone with ground station (Phase 1)"""
        pkey_bytes = self.pkey_dr.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        print(f"Registering with ground station at {gs_host}:{gs_port}")

        gs_id_response = self.send_request_to_gs(
            gs_host,
            gs_port,
            {'action': 'get_ground_station_id'}
        )

        if gs_id_response['status'] != 'success':
            print(f"Failed to get ground station ID: {gs_id_response.get('message', 'Unknown error')}")
            return False

        gs_id = gs_id_response['id']
        print(f"Ground station ID: {gs_id}")

        print(f"Sending registration data: {self.ps_id_dr}, challenge and response data, and public key")
        response = self.send_request_to_gs(
            gs_host,
            gs_port,
            {
                'action': 'register_drone',
                'ps_id_dr': self.ps_id_dr,
                'ch_dr': self.ch_dr,
                'res_dr': self.res_dr,
                'pkey_bytes': pkey_bytes,
                'drone_id': self.id_dr  # Send the real drone ID as well
            }
        )

        if response["status"] == "success":
            self.tree_id = response.get("tree_id")
            self.ground_station_id = gs_id

            # Store Merkle proof information
            if "merkle_proof" in response:
                self.merkle_proof = response["merkle_proof"]
                self.leaf_position = self.merkle_proof.get("leaf_position")
                self.my_leaf_hash = bytes.fromhex(self.merkle_proof.get("leaf_hash", ""))

            # Store root hashes
            if "root_hashes" in response:
                self.root_hashes = response["root_hashes"]

            print(f"Successfully registered with ground station.")
            print(f"Tree ID: {self.tree_id}")
            print(f"Ground Station ID: {self.ground_station_id}")

            return True
        else:
            print(f"Registration failed: {response.get('message', 'Unknown error')}")
            return False

    def authenticate_with_ground_station(self, gs_host, gs_port):
        """Authenticate with ground station (Phase 4)"""
        if not self.ground_station_id:
            print("Drone not registered with any ground station")
            return {"status": "error", "message": "Drone not registered with any ground station"}

        ts1 = int(time.time())

        gs_pkey_response = self.send_request_to_gs(
            gs_host,
            gs_port,
            {'action': 'get_public_key'}
        )

        if gs_pkey_response['status'] != 'success':
            print(f"Failed to get ground station public key: {gs_pkey_response.get('message', 'Unknown error')}")
            return gs_pkey_response

        gs_pkey = gs_pkey_response['public_key']

        message = f"{self.ps_id_dr}{ts1}".encode()

        m1 = hashlib.sha256(message + gs_pkey).digest()

        print(f"Initiating authentication with ground station...")
        response = self.send_request_to_gs(
            gs_host,
            gs_port,
            {
                'action': 'initiate_drone_authentication',
                'm1': m1,
                'ps_id_dr': self.ps_id_dr,
                'ts1': ts1
            }
        )

        if response["status"] != "success":
            print(f"Authentication initiation failed: {response.get('message', 'Unknown error')}")
            return response

        ch_dr = response["challenge"]
        new_ch_dr = response["new_challenge"]
        ts3 = response["timestamp"]
        ts4 = int(time.time())

        if ts4 - ts3 > 300:
            print("Authentication timeout")
            return {"status": "error", "message": "Authentication timeout"}

        res_dr = self.puf_function(ch_dr)  # Calculate response using PUF
        new_res_dr = self.puf_function(new_ch_dr)
        print(f"Generated challenge responses")

        ts5 = int(time.time())

        message = f"{ch_dr.hex()}{res_dr.hex()}{ts5}".encode()

        m3 = hashlib.sha256(message + gs_pkey).digest()

        print(f"Sending verification response to ground station...")
        final_response = self.send_request_to_gs(
            gs_host,
            gs_port,
            {
                'action': 'verify_drone_response',
                'm3': m3,
                'ch_dr': new_ch_dr,
                'new_res_dr': new_res_dr,
                'res_dr': res_dr,
                'ts5': ts5,
                'ps_id_dr': self.ps_id_dr
            }
        )

        if final_response["status"] == "success":
            if "session_key" in final_response:
                self.session_keys[self.ground_station_id] = final_response["session_key"]
                print(
                    f"Successfully authenticated with ground station. Session key: {final_response['session_key'][:10]}...")

            # Update Merkle proof if provided
            if "merkle_proof" in final_response and "root_hashes" in final_response:
                self.merkle_proof = final_response["merkle_proof"]
                self.root_hashes = final_response["root_hashes"]
                self.leaf_position = self.merkle_proof.get("leaf_position")
                self.my_leaf_hash = bytes.fromhex(self.merkle_proof.get("leaf_hash", ""))
                print("Received updated Merkle proof and root hashes from Ground Station")

        return final_response

    def authenticate_user(self, m1, ps_id_u, tk_u, ts1):
        """Authenticate a user request (Phase 2)"""
        print(f"Authenticating user {ps_id_u}")
        ts2 = int(time.time())

        if ts2 - ts1 > 300:
            print("Authentication timeout")
            return {"status": "error", "message": "Authentication timeout"}

        # Verify PUF-based token match if we have a token set
        if self.tk_dr:
            combined = self.id_dr.encode() + tk_u.encode()
            expected_tk_dr = hashlib.sha256(combined).digest()

            if self.tk_dr != expected_tk_dr:
                print("Invalid token")
                return {"status": "error", "message": "Invalid token"}

        ts3 = int(time.time())

        sk = hashlib.sha256(f"{self.id_dr}{ts3}".encode() + self.ps_id_dr.encode()).digest()

        print(f"User {ps_id_u} successfully authenticated")
        return {
            "status": "success",
            "session_key": sk.hex(),
            "timestamp": ts3,
            "expiry": ts3 + 3600
        }

    def authenticate_drone(self, remote_drone_id, remote_merkle_proof, nonce):
        """
        Authenticate another drone using Merkle proofs (Phase 5).

        Args:
            remote_drone_id: The ID of the remote drone
            remote_merkle_proof: The Merkle proof from the remote drone
            nonce: A random nonce for freshness

        Returns:
            Authentication response
        """
        print(f"Authenticating remote drone {remote_drone_id}")

        # Verify we have the necessary data for authentication
        if not self.root_hashes:
            return {"status": "error",
                    "message": "No root hashes available. Please authenticate with ground station first."}

        if not self.merkle_proof:
            return {"status": "error",
                    "message": "No Merkle proof available. Please authenticate with ground station first."}

        # Extract data from the remote drone's Merkle proof
        if not remote_merkle_proof.get("success", False):
            return {"status": "error", "message": "Invalid remote Merkle proof"}

        remote_tree_id = remote_merkle_proof.get("tree_id")
        remote_leaf_hash = bytes.fromhex(remote_merkle_proof.get("leaf_hash", ""))
        remote_proof_elements = remote_merkle_proof.get("proof_elements", [])

        # Check if the remote tree ID is valid
        if remote_tree_id >= len(self.root_hashes):
            return {"status": "error", "message": f"Unknown tree ID: {remote_tree_id}"}

        # Verify the remote drone's Merkle proof against our root hashes
        expected_root_hash = bytes.fromhex(self.root_hashes[remote_tree_id])
        current_hash = remote_leaf_hash

        for proof_item in remote_proof_elements:
            sibling_hash = bytes.fromhex(proof_item["hash"])

            # Order the hashes based on left/right positioning
            if proof_item["is_left"]:
                combined = sibling_hash + current_hash
            else:
                combined = current_hash + sibling_hash

            # Calculate the parent hash
            current_hash = hashlib.sha256(combined).digest()

        # Check if the calculated root matches the expected root
        if current_hash != expected_root_hash:
            return {"status": "error", "message": "Merkle proof verification failed"}

        # If verification is successful, generate a session key
        ts = int(time.time())
        session_key = hashlib.sha256(
            f"{self.id_dr}{remote_drone_id}{nonce}{ts}".encode()
        ).hexdigest()

        # Store the session key
        self.session_keys[remote_drone_id] = session_key

        print(f"Successfully authenticated drone {remote_drone_id}")
        return {
            "status": "success",
            "session_key": session_key,
            "timestamp": ts,
            "expiry": ts + 3600
        }

    def initiate_drone_authentication(self, remote_drone_host, remote_drone_port):
        """
        Initiate authentication with another drone (Phase 5).

        Args:
            remote_drone_host: The host of the remote drone
            remote_drone_port: The port of the remote drone

        Returns:
            Authentication result
        """
        print(f"Initiating authentication with drone at {remote_drone_host}:{remote_drone_port}")

        # Verify we have the necessary data for authentication
        if not self.merkle_proof:
            return {"status": "error",
                    "message": "No Merkle proof available. Please authenticate with ground station first."}

        # Get the remote drone's ID
        drone_id_response = self.send_request_to_drone(
            remote_drone_host,
            remote_drone_port,
            {'action': 'get_drone_id'}
        )

        if drone_id_response['status'] != 'success':
            print(f"Failed to get remote drone ID: {drone_id_response.get('message', 'Unknown error')}")
            return drone_id_response

        remote_drone_id = drone_id_response['id']
        print(f"Remote drone ID: {remote_drone_id}")

        # Generate a nonce for freshness
        nonce = secrets.token_hex(16)

        # Send authentication request with our Merkle proof
        response = self.send_request_to_drone(
            remote_drone_host,
            remote_drone_port,
            {
                'action': 'authenticate_drone',
                'drone_id': self.id_dr,
                'merkle_proof': self.merkle_proof,
                'nonce': nonce
            }
        )

        if response["status"] != "success":
            print(f"Authentication with remote drone failed: {response.get('message', 'Unknown error')}")
            return response

        # Verify the remote drone's response
        if "session_key" in response:
            session_key = response["session_key"]
            self.session_keys[remote_drone_id] = session_key
            print(f"Successfully authenticated with remote drone. Session key: {session_key[:10]}...")

        return response

    def set_token(self, tk_dr):
        """Set the drone token (from ground station)"""
        self.tk_dr = tk_dr
        print(f"Token set for drone")

    def get_public_key(self):
        return self.pkey_dr.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_merkle_proof(self):
        """Get the current Merkle proof for this drone"""
        if not self.merkle_proof:
            print("No Merkle proof available. Please authenticate with ground station first.")
            return None
        return self.merkle_proof

    def update_merkle_proof_from_gs(self, gs_host, gs_port):
        """Request an updated Merkle proof from the ground station"""
        if not self.ground_station_id or not self.ps_id_dr:
            print("Drone not registered with any ground station")
            return False

        response = self.send_request_to_gs(
            gs_host,
            gs_port,
            {
                'action': 'get_merkle_proof',
                'ps_id_dr': self.ps_id_dr
            }
        )

        if response["status"] != "success":
            print(f"Failed to get updated Merkle proof: {response.get('message', 'Unknown error')}")
            return False

        if "merkle_proof" in response and "root_hashes" in response:
            self.merkle_proof = response["merkle_proof"]
            self.root_hashes = response["root_hashes"]
            self.leaf_position = self.merkle_proof.get("leaf_position")
            self.my_leaf_hash = bytes.fromhex(self.merkle_proof.get("leaf_hash", ""))
            print("Successfully updated Merkle proof and root hashes")
            return True

        return False

    def update_root_hashes_from_gs(self, gs_host, gs_port):
        """Request updated root hashes from the ground station"""
        if not self.ground_station_id:
            print("Drone not registered with any ground station")
            return False

        response = self.send_request_to_gs(
            gs_host,
            gs_port,
            {'action': 'get_root_hashes'}
        )

        if response["status"] != "success":
            print(f"Failed to get updated root hashes: {response.get('message', 'Unknown error')}")
            return False

        if "root_hashes" in response:
            self.root_hashes = response["root_hashes"]
            print("Successfully updated root hashes")
            return True

        return False

    def send_request_to_gs(self, host, port, request):
        """Send a request to the ground station server and return the response"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((host, port))

                request_data = pickle.dumps(request)
                request_len = len(request_data).to_bytes(4, byteorder='big')

                sock.sendall(request_len + request_data)

                response_len_bytes = sock.recv(4)
                response_len = int.from_bytes(response_len_bytes, byteorder='big')

                response_data = b''
                while len(response_data) < response_len:
                    packet = sock.recv(response_len - len(response_data))
                    if not packet:
                        break
                    response_data += packet

                response = pickle.loads(response_data)
                return response

        except ConnectionRefusedError:
            return {"status": "error", "message": f"Connection refused to {host}:{port}"}
        except Exception as e:
            return {"status": "error", "message": f"Error communicating with server: {str(e)}"}

    def send_request_to_drone(self, host, port, request):
        """Send a request to another drone server and return the response"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((host, port))

                request_data = pickle.dumps(request)
                request_len = len(request_data).to_bytes(4, byteorder='big')

                sock.sendall(request_len + request_data)

                response_len_bytes = sock.recv(4)
                response_len = int.from_bytes(response_len_bytes, byteorder='big')

                response_data = b''
                while len(response_data) < response_len:
                    packet = sock.recv(response_len - len(response_data))
                    if not packet:
                        break
                    response_data += packet

                response = pickle.loads(response_data)
                return response

        except ConnectionRefusedError:
            return {"status": "error", "message": f"Connection refused to {host}:{port}"}
        except Exception as e:
            return {"status": "error", "message": f"Error communicating with server: {str(e)}"}


class DroneServer:
    def __init__(self, drone, host='0.0.0.0', port=DRONE_PORT):
        self.drone = drone
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        """Start the drone server"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        print(f"Drone Server started on {self.host}:{self.port}")
        print(f"Drone ID: {self.drone.id_dr}")

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

                # Deserialize the request
                request = pickle.loads(data)
                print(f"Received request: {request['action']} from {address}")

                # Process the request based on action
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
        if action == 'authenticate_user':
            return self.drone.authenticate_user(
                request['m1'],
                request['ps_id_u'],
                request['tk_u'],
                request['ts1']
            )
        elif action == 'authenticate_drone':
            return self.drone.authenticate_drone(
                request['drone_id'],
                request['merkle_proof'],
                request['nonce']
            )
        elif action == 'get_public_key':
            return {
                'status': 'success',
                'public_key': self.drone.get_public_key()
            }
        elif action == 'get_drone_id':
            return {
                'status': 'success',
                'id': self.drone.id_dr
            }
        elif action == 'get_merkle_proof':
            merkle_proof = self.drone.get_merkle_proof()
            if merkle_proof:
                return {
                    'status': 'success',
                    'merkle_proof': merkle_proof
                }
            else:
                return {
                    'status': 'error',
                    'message': 'No Merkle proof available'
                }
        elif action == 'set_token':
            self.drone.set_token(request['token'])
            return {'status': 'success'}
        elif action == 'receive_message':
            print(f"Received encrypted message from {request.get('from', 'unknown')}")
            return {'status': 'success'}
        else:
            return {'status': 'error', 'message': f'Unknown action: {action}'}


class SecureComms:
    @staticmethod
    def encrypt_message(message, key):
        if isinstance(key, str):
            key = bytes.fromhex(key)

        if len(key) < 32:
            key = key.ljust(32, b'\0')
        elif len(key) > 32:
            key = key[:32]

        iv = os.urandom(12)

        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=None
        ).encryptor()

        if isinstance(message, str):
            message = message.encode()

        ciphertext = encryptor.update(message) + encryptor.finalize()

        return {
            "iv": iv,
            "ciphertext": ciphertext,
            "tag": encryptor.tag
        }

    @staticmethod
    def decrypt_message(encrypted_data, key):
        if isinstance(key, str):
            key = bytes.fromhex(key)

        if len(key) < 32:
            key = key.ljust(32, b'\0')
        elif len(key) > 32:
            key = key[:32]

        iv = encrypted_data["iv"]
        ciphertext = encrypted_data["ciphertext"]
        tag = encrypted_data["tag"]

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=None
        ).decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        try:
            return plaintext.decode()
        except UnicodeDecodeError:
            return plaintext


def run_drone_server():
    parser = argparse.ArgumentParser(description="Drone Authentication System - Drone Server")
    parser.add_argument('--gs-host', default=GS_HOST, help='Ground Station host IP')
    parser.add_argument('--gs-port', type=int, default=GS_PORT, help='Ground Station port')
    parser.add_argument('--port', type=int, default=DRONE_PORT, help='Drone server port')
    args = parser.parse_args()

    drone = Drone()
    server = DroneServer(drone, port=args.port)

    # Start server in a separate thread
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()

    while True:
        print("\n=== Drone Server Menu ===")
        print("1. Register with Ground Station")
        print("2. Authenticate with Ground Station")
        print("3. Show active sessions")
        print("4. Update Merkle proof from Ground Station")
        print("5. Update root hashes from Ground Station")
        print("6. Authenticate with another Drone")
        print("7. View Merkle proof and root hashes")
        print("8. Exit")

        choice = input("Enter your choice (1-8): ")

        if choice == '1':
            success = drone.register_with_ground_station(args.gs_host, args.gs_port)
            if success:
                print(f"Successfully registered with Ground Station")
                print(f"Tree ID: {drone.tree_id}")
                print(f"Ground Station ID: {drone.ground_station_id}")

        elif choice == '2':
            if not drone.ground_station_id:
                print("Drone not registered with any Ground Station. Please register first.")
                continue

            auth_result = drone.authenticate_with_ground_station(args.gs_host, args.gs_port)
            if auth_result['status'] == 'success':
                print(f"Authentication successful with Ground Station")
                if 'session_key' in auth_result:
                    print(f"Session key: {auth_result['session_key'][:10]}...")
                if 'expiry' in auth_result:
                    print(f"Expires: {auth_result['expiry']}")
            else:
                print(f"Authentication failed: {auth_result.get('message', 'Unknown error')}")

        elif choice == '3':
            print("\n=== Active Sessions ===")
            if not drone.session_keys:
                print("No active sessions")
            else:
                for entity_id, session_key in drone.session_keys.items():
                    print(f"Entity ID: {entity_id}")
                    print(f"Session Key: {session_key[:10]}...")
                    print("---")

        elif choice == '4':
            if not drone.ground_station_id:
                print("Drone not registered with any Ground Station. Please register first.")
                continue

            success = drone.update_merkle_proof_from_gs(args.gs_host, args.gs_port)
            if success:
                print("Successfully updated Merkle proof from Ground Station")

        elif choice == '5':
            if not drone.ground_station_id:
                print("Drone not registered with any Ground Station. Please register first.")
                continue

            success = drone.update_root_hashes_from_gs(args.gs_host, args.gs_port)
            if success:
                print("Successfully updated root hashes from Ground Station")

        elif choice == '6':
            if not drone.merkle_proof or not drone.root_hashes:
                print("Merkle proof or root hashes not available. Please authenticate with Ground Station first.")
                continue

            remote_drone_host = input("Enter the IP address of the remote drone: ")
            remote_drone_port = int(input("Enter the port of the remote drone: "))

            auth_result = drone.initiate_drone_authentication(remote_drone_host, remote_drone_port)
            if auth_result['status'] == 'success':
                print(f"Authentication successful with remote drone")
                if 'session_key' in auth_result:
                    print(f"Session key: {auth_result['session_key'][:10]}...")
                if 'expiry' in auth_result:
                    print(f"Expires: {auth_result['expiry']}")
            else:
                print(f"Authentication failed: {auth_result.get('message', 'Unknown error')}")

        elif choice == '7':
            print("\n=== Merkle Proof and Root Hashes ===")
            if drone.merkle_proof:
                print(f"Tree ID: {drone.tree_id}")
                print(f"Leaf Position: {drone.leaf_position}")
                print(f"My Leaf Hash: {drone.my_leaf_hash.hex() if drone.my_leaf_hash else 'None'}")

                if 'proof_elements' in drone.merkle_proof:
                    print("\nProof Elements:")
                    for i, element in enumerate(drone.merkle_proof['proof_elements']):
                        print(f"  Element {i + 1}:")
                        print(f"    Position: {element.get('position')}")
                        print(f"    Hash: {element.get('hash')[:10]}...")
                        print(f"    Is Left: {element.get('is_left')}")
            else:
                print("No Merkle proof available")

            if drone.root_hashes:
                print("\nRoot Hashes:")
                for i, root_hash in enumerate(drone.root_hashes):
                    print(f"  Tree {i}: {root_hash[:10]}...")
            else:
                print("No root hashes available")

        elif choice == '8':
            print("Exiting...")
            sys.exit(0)

        else:
            print("Invalid choice. Please enter a number between 1 and 8.")


if __name__ == "__main__":
    run_drone_server()
