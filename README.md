# Drone Authentication System using Merkle Trees & PUF

## Overview
This project implements a **secure authentication framework** for drones, ground stations, and users. It combines **Merkle Hash Trees**, **Physical Unclonable Functions (PUFs)**, and **lightweight cryptographic operations** (SHA-256, ECC, AES-GCM) to provide **mutual authentication** and **secure communication** across devices.

- **User**: Android/phone client for registration, authentication, and secure messaging.  
- **Drone**: Raspberry Pi-based client with PUF response generation and Merkle proof handling.  
- **Ground Station (GCS)**: Laptop server managing registration, authentication, and Merkle forest of drones.

## Features
- **User Registration & Authentication** with Ground Station  
- **Drone Registration & Authentication** using Merkle Proofs  
- **Mutual Drone–Drone Authentication** without Ground Station involvement  
- **PUF Integration** for unique hardware-bound authentication  
- **Performance Monitoring** of cryptographic operations across devices  

## Cryptographic Operations
- **SHA-256**: Hashing IDs, nonces, and token derivation  
- **ECC**: Public–private key generation  
- **AES-GCM**: Secure message encryption/decryption  
- **PUF**: Hardware-bound identity generation for drones  
- **Random Nonces & Timestamps**: Prevent replay attacks  

## Repository Structure
