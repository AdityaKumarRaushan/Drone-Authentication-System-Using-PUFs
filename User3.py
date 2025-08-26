import socket
import pickle
import hashlib
import secrets
import time
import sys
import argparse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Global configuration
GS_HOST = "192.168.137.1"
GS_PORT = 8000
DRONE_HOST = "192.168.137.233"
DRONE_PORT = 8001


class User:
    def __init__(self):
        self.id_u = self.generate_unique_id()
        self.nonce = secrets.token_bytes(16)
        self.tokens = {}
        self.registered_drones = {}
        self.session_keys = {}

        self.ps_id_u = self.generate_pseudo_identity()
        self.skey_u, self.pkey_u = self.generate_key_pair()

        print(f"User created with ID: {self.id_u}")
        print(f"Pseudo ID: {self.ps_id_u}")

    def generate_unique_id(self):
        return f"user-{secrets.token_hex(8)}"

    def generate_pseudo_identity(self):
        combined = self.id_u.encode() + self.nonce
        return hashlib.sha256(combined).hexdigest()

    def generate_key_pair(self):
        # Derive secret key material from pseudo-identity and nonce
        skey_material = hashlib.sha256(self.ps_id_u.encode() + self.nonce).digest()

        private_key = ec.derive_private_key(
            int.from_bytes(skey_material, 'big'),
            ec.SECP256R1()
        )
        public_key = private_key.public_key()

        return private_key, public_key

    def register_with_ground_station(self, gs_host, gs_port):
        """Register user with ground station (Phase 1)"""
        pkey_bytes = self.pkey_u.public_bytes(
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

        # Send registration data to ground station
        response = self.send_request_to_gs(
            gs_host,
            gs_port,
            {
                'action': 'register_user',
                'ps_id_u': self.ps_id_u,
                'pkey_bytes': pkey_bytes
            }
        )

        if response["status"] == "success":
            self.tokens[gs_id] = response["token"]
            print(f"Successfully registered with ground station. Token: {response['token'][:10]}...")
            return True
        else:
            print(f"Registration failed: {response.get('message', 'Unknown error')}")
            return False

    def authenticate_with_ground_station(self, gs_host, gs_port, gs_id):
        """User Authenticates with ground station (Phase 3)"""
        if gs_id not in self.tokens:
            print(f"Not registered with ground station {gs_id}")
            return {"status": "error", "message": "User not registered with this ground station"}

        ts1 = int(time.time())

        # Get ground station's public key
        gs_pkey_response = self.send_request_to_gs(
            gs_host,
            gs_port,
            {'action': 'get_public_key'}
        )

        if gs_pkey_response['status'] != 'success':
            print(f"Failed to get ground station public key: {gs_pkey_response.get('message', 'Unknown error')}")
            return gs_pkey_response

        gs_pkey = gs_pkey_response['public_key']

        message = f"{self.ps_id_u}{ts1}".encode()

        m1 = hashlib.sha256(message + gs_pkey).digest()

        print(f"Authenticating with ground station...")
        response = self.send_request_to_gs(
            gs_host,
            gs_port,
            {
                'action': 'authenticate_user',
                'm1': m1,
                'ps_id_u': self.ps_id_u,
                'ts1': ts1
            }
        )

        if response["status"] != "success":
            print(f"Authentication failed: {response.get('message', 'Unknown error')}")
            return response

        sk = response["session_key"]
        ts3 = response["timestamp"]
        ts4 = int(time.time())

        if ts4 - ts3 > 300:
            print("Authentication timeout")
            return {"status": "error", "message": "Authentication timeout"}

        # Store session key
        self.session_keys[gs_id] = sk
        print(f"Successfully authenticated with ground station. Session key: {sk[:10]}...")

        return {
            "status": "success",
            "session_key": sk,
            "expiry": ts4 + 3600
        }

    def initiate_drone_authentication(self, drone_host, drone_port, gs_id):
        """Initiate authentication with a drone (Phase 2)"""
        print(f"Initiating authentication with drone at {drone_host}:{drone_port}")

        # First get the drone ID
        drone_id_response = self.send_request_to_drone(
            drone_host,
            drone_port,
            {'action': 'get_drone_id'}
        )

        if drone_id_response['status'] != 'success':
            print(f"Failed to get drone ID: {drone_id_response.get('message', 'Unknown error')}")
            return drone_id_response

        drone_id = drone_id_response['id']
        print(f"Drone ID: {drone_id}")

        ts1 = int(time.time())

        ps_id_u_ts = hashlib.sha256(f"{self.id_u}{ts1}".encode()).hexdigest()

        if gs_id not in self.tokens:
            print(f"Not registered with ground station {gs_id}")
            return {"status": "error", "message": "User not registered with drone's ground station"}

        tk_u = self.tokens[gs_id]

        # Get drone's public key
        drone_pkey_response = self.send_request_to_drone(
            drone_host,
            drone_port,
            {'action': 'get_public_key'}
        )

        if drone_pkey_response['status'] != 'success':
            print(f"Failed to get drone public key: {drone_pkey_response.get('message', 'Unknown error')}")
            return drone_pkey_response

        drone_pkey = drone_pkey_response['public_key']

        message = f"{ps_id_u_ts}{tk_u}{ts1}".encode()

        # Encrypt M1 using drone's public key, For simplicity, we're using a hash
        m1 = hashlib.sha256(message + drone_pkey).digest()

        response = self.send_request_to_drone(
            drone_host,
            drone_port,
            {
                'action': 'authenticate_user',
                'm1': m1,
                'ps_id_u': ps_id_u_ts,
                'tk_u': tk_u,
                'ts1': ts1
            }
        )

        if response["status"] != "success":
            print(f"Authentication with drone failed: {response.get('message', 'Unknown error')}")
            return response

        sk = response["session_key"]
        ts3 = response["timestamp"]
        ts4 = int(time.time())

        if ts4 - ts3 > 300:
            print("Authentication timeout")
            return {"status": "error", "message": "Authentication timeout"}

        # Store session key
        self.session_keys[drone_id] = sk
        print(f"Successfully authenticated with drone. Session key: {sk[:10]}...")

        return {
            "status": "success",
            "session_key": sk,
            "expiry": ts4 + 3600
        }

    def get_public_key(self):
        """Return serialized public key"""
        return self.pkey_u.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

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
        """Send a request to the drone server and return the response"""
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


class SecureComms:
    @staticmethod
    def encrypt_message(message, key):
        if isinstance(key, str):
            key = bytes.fromhex(key)

        if len(key) < 32:
            key = key.ljust(32, b'\0')
        elif len(key) > 32:
            key = key[:32]

        # Generate a random 96-bit IV (nonce)
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


def run_user_client():
    parser = argparse.ArgumentParser(description="Drone Authentication System - User Client")
    parser.add_argument('--gs-host', default=GS_HOST, help='Ground Station host IP')
    parser.add_argument('--gs-port', type=int, default=GS_PORT, help='Ground Station port')
    parser.add_argument('--drone-host', default=DRONE_HOST, help='Drone host IP')
    parser.add_argument('--drone-port', type=int, default=DRONE_PORT, help='Drone port')
    args = parser.parse_args()

    user = User()

    while True:
        print("\n=== User Client Menu ===")
        print("1. Register with Ground Station")
        print("2. Authenticate with Ground Station")
        print("3. Authenticate with Drone")
        print("4. Send encrypted message to Ground Station")
        print("5. Send encrypted message to Drone")
        print("6. Exit")

        choice = input("Enter your choice (1-6): ")

        if choice == '1':
            success = user.register_with_ground_station(args.gs_host, args.gs_port)
            if success:
                gs_id_response = user.send_request_to_gs(
                    args.gs_host,
                    args.gs_port,
                    {'action': 'get_ground_station_id'}
                )
                if gs_id_response['status'] == 'success':
                    print(f"Registered with Ground Station ID: {gs_id_response['id']}")

        elif choice == '2':
            gs_id_response = user.send_request_to_gs(
                args.gs_host,
                args.gs_port,
                {'action': 'get_ground_station_id'}
            )

            if gs_id_response['status'] == 'success':
                gs_id = gs_id_response['id']
                auth_result = user.authenticate_with_ground_station(args.gs_host, args.gs_port, gs_id)
                if auth_result['status'] == 'success':
                    print(f"Authentication successful with Ground Station")
                    print(f"Session key: {auth_result['session_key'][:10]}...")
                    print(f"Expires: {auth_result['expiry']}")
                else:
                    print(f"Authentication failed: {auth_result.get('message', 'Unknown error')}")
            else:
                print(f"Failed to get Ground Station ID: {gs_id_response.get('message', 'Unknown error')}")

        elif choice == '3':
            gs_id_response = user.send_request_to_gs(
                args.gs_host,
                args.gs_port,
                {'action': 'get_ground_station_id'}
            )

            if gs_id_response['status'] == 'success':
                gs_id = gs_id_response['id']
                auth_result = user.initiate_drone_authentication(args.drone_host, args.drone_port, gs_id)
                if auth_result['status'] == 'success':
                    print(f"Authentication successful with Drone")
                    print(f"Session key: {auth_result['session_key'][:10]}...")
                    print(f"Expires: {auth_result['expiry']}")
                else:
                    print(f"Authentication failed: {auth_result.get('message', 'Unknown error')}")
            else:
                print(f"Failed to get Ground Station ID: {gs_id_response.get('message', 'Unknown error')}")

        elif choice == '4':
            gs_id_response = user.send_request_to_gs(
                args.gs_host,
                args.gs_port,
                {'action': 'get_ground_station_id'}
            )

            if gs_id_response['status'] == 'success':
                gs_id = gs_id_response['id']

                if gs_id in user.session_keys:
                    message = input("Enter message to send to Ground Station: ")
                    session_key = user.session_keys[gs_id]

                    encrypted = SecureComms.encrypt_message(message, session_key)

                    response = user.send_request_to_gs(
                        args.gs_host,
                        args.gs_port,
                        {
                            'action': 'receive_message',
                            'from': user.ps_id_u,
                            'encrypted_data': encrypted
                        }
                    )

                    if response['status'] == 'success':
                        print("Message sent successfully!")
                    else:
                        print(f"Failed to send message: {response.get('message', 'Unknown error')}")
                else:
                    print(f"No active session with Ground Station. Please authenticate first.")
            else:
                print(f"Failed to get Ground Station ID: {gs_id_response.get('message', 'Unknown error')}")

        elif choice == '5':
            drone_id_response = user.send_request_to_drone(
                args.drone_host,
                args.drone_port,
                {'action': 'get_drone_id'}
            )

            if drone_id_response['status'] == 'success':
                drone_id = drone_id_response['id']

                if drone_id in user.session_keys:
                    message = input("Enter message to send to Drone: ")
                    session_key = user.session_keys[drone_id]

                    encrypted = SecureComms.encrypt_message(message, session_key)

                    response = user.send_request_to_drone(
                        args.drone_host,
                        args.drone_port,
                        {
                            'action': 'receive_message',
                            'from': user.ps_id_u,
                            'encrypted_data': encrypted
                        }
                    )

                    if response['status'] == 'success':
                        print("Message sent successfully!")
                    else:
                        print(f"Failed to send message: {response.get('message', 'Unknown error')}")
                else:
                    print(f"No active session with Drone. Please authenticate first.")
            else:
                print(f"Failed to get Drone ID: {drone_id_response.get('message', 'Unknown error')}")

        elif choice == '6':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please enter a number between 1 and 6.")


if __name__ == "__main__":
    run_user_client()