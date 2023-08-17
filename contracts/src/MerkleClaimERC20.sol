// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.17;

/// ============ Imports ============

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol"; // OZ: MerkleProof
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title MerkleClaimERC20
/// @notice ERC20 claimable by members of a merkle tree
/// @author Anish Agnihotri <contact@anishagnihotri.com>
/// @dev Lightly modified from Anish's version to replace minting with simple safeTransfer and add a sweep method
contract MerkleClaimERC20 is Ownable {
    using SafeERC20 for IERC20;
    /// ============ Immutable storage ============

    /// @notice ERC20-claimee inclusion root
    bytes32 public immutable merkleRoot;

    /// @notice Our token address to distribute
    IERC20 public immutable token;

    /// ============ Mutable storage ============

    /// @notice Mapping of addresses who have claimed tokens
    mapping(address => bool) public hasClaimed;

    /// ============ Errors ============

    /// @notice Thrown if address has already claimed
    error AlreadyClaimed();
    /// @notice Thrown if address/amount are not part of Merkle tree
    error NotInMerkle();

    /// ============ Constructor ============

    /// @notice Creates a new MerkleClaimERC20 contract
    /// @param _merkleRoot of claimees
    /// @param _token to distribute
    constructor(bytes32 _merkleRoot, address _token) {
        merkleRoot = _merkleRoot; // Update root
        token = IERC20(_token);
    }

    /// ============ Events ============

    /// @notice Emitted after a successful token claim
    /// @param to recipient of claim
    /// @param amount of tokens claimed
    event Claim(address indexed to, uint256 amount);

    /// @notice Emitted after a successful token sweep
    /// @param token address of token to sweep to owner
    /// @param amount of tokens to sweep
    event Recovered(address token, uint256 amount);

    /// ============ Functions ============

    function check_claim(
        address to,
        uint256 amount,
        bytes32[] calldata proof
    ) external view returns (bool) {
        // Verify merkle proof, or revert if not in tree
        bytes32 leaf = keccak256(abi.encodePacked(to, amount));
        return MerkleProof.verify(proof, merkleRoot, leaf);
    }

    /// @notice Allows claiming tokens if address is part of merkle tree
    /// @param to address of claimee
    /// @param amount of tokens owed to claimee
    /// @param proof merkle proof to prove address and amount are in tree
    function claim(
        address to,
        uint256 amount,
        bytes32[] calldata proof
    ) external {
        // Throw if address has already claimed tokens
        if (hasClaimed[to]) revert AlreadyClaimed();

        // Verify merkle proof, or revert if not in tree
        bytes32 leaf = keccak256(abi.encodePacked(to, amount));
        bool isValidLeaf = MerkleProof.verify(proof, merkleRoot, leaf);
        if (!isValidLeaf) revert NotInMerkle();

        // Set address to claimed
        hasClaimed[to] = true;

        // Transfer tokens to address
        token.safeTransfer(to, amount);

        // Emit claim event
        emit Claim(to, amount);
    }

    /// @notice Use this in case someone accidentally sends tokens here
    /// @dev May only be called by owner
    /// @param tokenAddress of token to sweep
    /// @param tokenAmount of tokens to sweep
    function recoverERC20(address tokenAddress, uint256 tokenAmount)
        external
        onlyOwner
    {
        IERC20(tokenAddress).safeTransfer(owner(), tokenAmount);
        emit Recovered(tokenAddress, tokenAmount);
    }
}
