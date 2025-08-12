// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "@openzeppelin/contracts@5.0.1/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts@5.0.1/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts@5.0.1/access/Ownable.sol";
import "@openzeppelin/contracts@5.0.1/utils/Pausable.sol";
import "@openzeppelin/contracts@5.0.1/utils/cryptography/ECDSA.sol"; // Tetap pertahankan ECDSA jika digunakan di mintWithSig

/// @title Rain Cloud Protocol (RCP)
/// @notice ERC20 token pegged 1:1 with IDR with gasless minting capabilities
/// @dev Features:
/// - Initial supply optional (constructor parameter)
/// - Uncapped supply (owner can mint more as needed)
/// - EIP-2612 permit for gasless approvals
/// - EIP-712 gasless minting
/// - Burn functionality
/// - Pausable functionality for emergency situations
contract RainCloudProtocol is ERC20, ERC20Permit, Ownable, Pausable {
    using ECDSA for bytes32; // ECDSA masih dibutuhkan untuk recover signature

    /// @dev Tracking nonces for mintWithSig to prevent replay attacks
    mapping(address => uint256) public mintNonces;

    /// @dev EIP-712 typehash for gasless minting. Immutable for gas efficiency.
    bytes32 public immutable MINT_TYPEHASH =
        keccak256(
            "Mint(address to,uint256 amount,uint256 nonce,uint256 deadline)"
        );

    /// @param initialSupply Initial token supply in wei (set to 0 for no initial mint)
    /// @param initialOwner The address that will receive the initial supply and become the owner.
    constructor(uint256 initialSupply, address initialOwner)
        ERC20("Rain Cloud Protocol", "RCP")
        ERC20Permit("Rain Cloud Protocol")
        Ownable(initialOwner)
    {
        if (initialSupply > 0) {
            _mint(initialOwner, initialSupply);
        }
    }

    // ============== Gasless Mint ==============
    /// @notice Mint tokens via owner's EIP-712 signature
    /// @dev Relayer submits transaction, recipient pays no gas.
    /// @param to Recipient address
    /// @param amount Amount to mint (in wei)
    /// @param deadline Signature expiration timestamp
    /// @param v,r,s Signature components from owner
    function mintWithSig(
        address to,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused {
        require(block.timestamp <= deadline, "RCP: Signature expired");
        require(to != address(0), "RCP: Invalid recipient");

        uint256 nonce = mintNonces[to];
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(MINT_TYPEHASH, to, amount, nonce, deadline))
        );

        require(digest.recover(v, r, s) == owner(), "RCP: Invalid signature");

        mintNonces[to] = nonce + 1; // Prevent replay attacks
        _mint(to, amount);
    }

    // ============== Owner Functions ==============
    /// @notice Standard mint function (owner only)
    /// @dev No supply cap - owner can mint as needed
    function mint(address to, uint256 amount) external onlyOwner whenNotPaused {
        require(to != address(0), "RCP: Invalid recipient");
        _mint(to, amount);
    }

    // ============== Burn Functions ==============
    /// @notice Burn tokens from caller's balance
    function burn(uint256 amount) external whenNotPaused {
        _burn(msg.sender, amount);
    }

    /// @notice Burn tokens from another account using allowance
    function burnFrom(address account, uint256 amount) external whenNotPaused {
        _spendAllowance(account, msg.sender, amount);
        _burn(account, amount);
    }

    // ============== Pausable Functions ==============
    /// @notice Pauses all token operations.
    /// @dev Can only be called by the contract owner.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses all token operations.
    /// @dev Can only be called by the contract owner.
    function unpause() external onlyOwner {
        _unpause();
    }

    // ============== Utility Functions ==============
    /// @notice Convert totalSupply from wei to token units
    /// @return Supply in whole token units (1 RCP = 1e18 wei)
    function totalSupplyInTokens() external view returns (uint256) {
        return totalSupply() / (10**decimals());
    }

    // ============== Overrides ==============
    // The functions below are overridden to allow for future extensions.
    // They are required by the compiler in this inheritance structure.
    function _update(
        address from,
        address to,
        uint256 amount
    )
        internal
        override(
            ERC20 // Remove Pausable from the override list
        )
    {
        super._update(from, to, amount);
    }

    // Override ini tidak lagi diperlukan jika _update di-override
    // function _burn(address account, uint256 amount)
    //     internal
    //     override(ERC20)
    // {
    //     super._burn(account, amount);
    // }

    // Override ini tidak lagi diperlukan jika _update di-override
    // function _mint(address account, uint256 amount)
    //     internal
    //     override(ERC20)
    // {
    //     super._mint(account, amount);
    // }
}
