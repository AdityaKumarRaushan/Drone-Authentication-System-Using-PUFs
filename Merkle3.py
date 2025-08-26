import hashlib
import secrets
from typing import List, Dict, Tuple, Optional, Any


class MerkleTree:
    """
    Binary heap-based Merkle tree implementation for drone authentication.
    Each tree has 32 fixed leaf nodes and a total of 63 nodes.
    """
    # Constants
    LEAF_COUNT = 32
    TOTAL_NODES = 63
    EMPTY_HASH = hashlib.sha256(b"EMPTY_LEAF").digest()

    def __init__(self, tree_id: int):
        self.tree_id = tree_id
        # Initialize the tree as a binary heap (array representation)
        self.nodes = [self.EMPTY_HASH] * (self.TOTAL_NODES + 1)
        self.drone_positions = {}  # drone IDs -> positions
        self.filled_positions = set()
        # Track if the tree is dirty (needs recalculation if some addition of drone or removal of any drone)
        self.is_dirty = False
        # Track affected drones when tree is modified
        self.affected_drones = set()

    def parent_ind(self, index: int) -> int:
        return index // 2

    def left_ind(self, index: int) -> int:
        return index * 2

    def right_ind(self, index: int) -> int:
        return index * 2 + 1

    def leaf_start_ind(self) -> int:
        """Get the starting index of leaf nodes in the binary heap."""
        return self.TOTAL_NODES + 1 - self.LEAF_COUNT

    def cal_node_hash(self, index: int) -> bytes:
        """Calculate the hash of a node based on its children."""
        left_child = self.left_ind(index)
        right_child = self.right_ind(index)

        # If we're at a leaf node, return its hash
        if left_child > self.TOTAL_NODES:
            return self.nodes[index]

        # Combine left and right child hashes
        left_hash = self.nodes[left_child]
        right_hash = self.nodes[right_child]
        combined = left_hash + right_hash
        return hashlib.sha256(combined).digest()

    def _update_path_to_root(self, leaf_index: int) -> None:
        """Update the path from a leaf to the root after a leaf is updated."""
        # Now update the hashes up to the root
        current = self.parent_ind(leaf_index)
        while current > 0:
            self.nodes[current] = self.cal_node_hash(current)
            current = self.parent_ind(current)


    def add_drone(self, drone_id: str, drone_hash: bytes) -> int:
        """
        Add a drone to the Merkle tree.

        Args:
            drone_id: Unique identifier for the drone
            drone_hash: Hash of the drone's identity information

        Returns:
            The leaf position of the added drone
        """
        # Check if drone already exists
        if drone_id in self.drone_positions:
            return self.drone_positions[drone_id]

        # Find an empty leaf position
        leaf_start = self.leaf_start_ind()
        for i in range(self.LEAF_COUNT):
            leaf_pos = leaf_start + i
            if leaf_pos not in self.filled_positions:
                # Assign this position to the drone
                self.nodes[leaf_pos] = drone_hash
                self.drone_positions[drone_id] = leaf_pos
                self.filled_positions.add(leaf_pos)

                # Update the path to the root
                self._update_path_to_root(leaf_pos)

                return leaf_pos

        # No empty positions found
        return -1

    def remove_drone(self, drone_id: str) -> bool:
        """
        Remove a drone from the Merkle tree.

        Args:
            drone_id: Unique identifier for the drone

        Returns:
            True if drone was successfully removed, False otherwise
        """
        if drone_id not in self.drone_positions:
            return False

        # Get the leaf position and clear it
        leaf_pos = self.drone_positions[drone_id]
        self.nodes[leaf_pos] = self.EMPTY_HASH
        self.filled_positions.remove(leaf_pos)
        del self.drone_positions[drone_id]

        # Update the path to the root
        self._update_path_to_root(leaf_pos)

        return True

    def get_root_hash(self) -> bytes:
        """Get the root hash of the Merkle tree."""
        return self.nodes[1]

    def is_full(self) -> bool:
        """Check if the tree is full (all leaf nodes are filled)."""
        return len(self.filled_positions) >= self.LEAF_COUNT

    def generate_merkle_proof(self, drone_id: str) -> Dict[str, Any]:
        """
        Generate a Merkle proof for a drone.

        Args:
            drone_id: Unique identifier for the drone

        Returns:
            A dictionary containing the proof elements and associated metadata
        """
        if drone_id not in self.drone_positions:
            return {"success": False, "message": "Drone not found in tree"}

        leaf_pos = self.drone_positions[drone_id]
        proof_elements = []

        current = leaf_pos
        while current > 1:  # Stop at the root
            # Get the sibling node
            is_left = current % 2 == 0  # Even indices are left children
            sibling = current + 1 if is_left else current - 1

            # Add the sibling to the proof
            proof_elements.append({
                "position": sibling,
                "hash": self.nodes[sibling].hex(),
                "is_left": not is_left  # The sibling's position relative to the path
            })

            # Move up to the parent
            current = self.parent_ind(current)

        return {
            "success": True,
            "tree_id": self.tree_id,
            "leaf_position": leaf_pos,
            "leaf_hash": self.nodes[leaf_pos].hex(),
            "proof_elements": proof_elements,
            "root_hash": self.get_root_hash().hex()
        }

    def get_affected_drones(self) -> set:
        """Get the set of drone IDs affected by the last tree modification."""
        return self.affected_drones.copy()

    @staticmethod
    def verify_merkle_proof(leaf_hash: bytes, proof_elements: List[Dict[str, Any]], expected_root_hash: bytes) -> bool:
        """
        Verify a Merkle proof against an expected root hash.

        Args:
            leaf_hash: The hash of the leaf node being verified
            proof_elements: The Merkle proof elements
            expected_root_hash: The expected root hash to verify against

        Returns:
            True if the proof is valid, False otherwise
        """
        current_hash = leaf_hash

        for proof_item in proof_elements:
            sibling_hash = bytes.fromhex(proof_item["hash"])

            # Order the hashes based on left/right positioning
            if proof_item["is_left"]:
                combined = sibling_hash + current_hash
            else:
                combined = current_hash + sibling_hash

            # Calculate the parent hash
            current_hash = hashlib.sha256(combined).digest()

        # Check if the calculated root matches the expected root
        return current_hash == expected_root_hash


class MerkleForest:
    """
    A collection of Merkle trees for scalable drone authentication.
    """

    def __init__(self):
        self.trees = []  # Array of MerkleTree objects
        self.drone_to_tree = {}  # Map drone_id to tree_id for quick lookup

    def _find_or_create_available_tree(self) -> Tuple[int, MerkleTree]:
        """
        Find an available tree or create a new one.

        Returns:
            Tuple of (tree_id, MerkleTree)
        """
        # Check existing trees
        for i, tree in enumerate(self.trees):
            if not tree.is_full():
                return i, tree

        # Create a new tree
        new_tree_id = len(self.trees)
        new_tree = MerkleTree(new_tree_id)
        self.trees.append(new_tree)
        return new_tree_id, new_tree

    def add_drone(self, drone_id: str, drone_hash: bytes) -> Tuple[int, int]:
        """
        Add a drone to the forest.

        Args:
            drone_id: Unique identifier for the drone
            drone_hash: Hash of the drone's identity information

        Returns:
            Tuple of (tree_id, leaf_position)
        """
        print("find tree")
        tree_id, tree = self._find_or_create_available_tree()
        print("tree found")
        print("treeid -> ", tree_id)
        print("tree -> ", tree)
        print("finding leaf pos")
        leaf_pos = tree.add_drone(drone_id, drone_hash)
        print("found leaf pos")

        if leaf_pos != -1:
            self.drone_to_tree[drone_id] = tree_id

        return tree_id, leaf_pos

    def remove_drone(self, drone_id: str) -> bool:
        """
        Remove a drone from the forest.

        Args:
            drone_id: Unique identifier for the drone

        Returns:
            True if drone was successfully removed, False otherwise
        """
        if drone_id not in self.drone_to_tree:
            return False

        tree_id = self.drone_to_tree[drone_id]
        result = self.trees[tree_id].remove_drone(drone_id)

        if result:
            del self.drone_to_tree[drone_id]

        return result

    def get_root_hashes(self) -> List[bytes]:
        """Get the root hashes of all trees in the forest."""
        return [tree.get_root_hash() for tree in self.trees]

    def get_root_hashes_hex(self) -> List[str]:
        """Get the root hashes of all trees in the forest as hex strings."""
        return [tree.get_root_hash().hex() for tree in self.trees]

    def generate_merkle_proof(self, drone_id: str) -> Dict[str, Any]:
        """
        Generate a Merkle proof for a drone.

        Args:
            drone_id: Unique identifier for the drone

        Returns:
            A dictionary containing the proof and metadata
        """
        if drone_id not in self.drone_to_tree:
            return {"success": False, "message": "Drone not found in forest"}

        tree_id = self.drone_to_tree[drone_id]
        return self.trees[tree_id].generate_merkle_proof(drone_id)

    def get_tree_size(self) -> int:
        """Get the number of trees in the forest."""
        return len(self.trees)

    def get_affected_drones_by_tree(self, tree_id: int) -> set:
        """Get the set of drone IDs affected by the last modification to a specific tree."""
        if tree_id >= len(self.trees):
            return set()

        return self.trees[tree_id].get_affected_drones()

    def get_tree_id_for_drone(self, drone_id: str) -> Optional[int]:
        """Get the tree ID for a specific drone."""
        return self.drone_to_tree.get(drone_id)

    @staticmethod
    def verify_merkle_proof(leaf_hash: bytes, proof_elements: List[Dict[str, Any]], root_hashes: List[bytes],
                            tree_id: int) -> bool:
        """
        Verify a Merkle proof against an array of root hashes.

        Args:
            leaf_hash: The hash of the leaf node being verified
            proof_elements: The Merkle proof elements
            root_hashes: List of all root hashes in the forest
            tree_id: The tree ID to check against

        Returns:
            True if the proof is valid, False otherwise
        """
        if tree_id >= len(root_hashes):
            return False

        expected_root_hash = root_hashes[tree_id]
        return MerkleTree.verify_merkle_proof(leaf_hash, proof_elements, expected_root_hash)
