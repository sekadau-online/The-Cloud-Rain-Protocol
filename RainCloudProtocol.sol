// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title Rain Cloud Protocol (RCP)
/// @notice ERC20 token pegged 1:1 with IDR with gasless minting capabilities
/// @dev Features:
/// - Initial supply optional (constructor parameter)
/// - Uncapped supply (owner can mint more as needed)
/// - EIP-2612 permit for gasless approvals
/// - EIP-712 gasless minting
/// - Burn functionality
contract RainCloudProtocol is ERC20, ERC20Permit, Ownable {
    using ECDSA for bytes32;

    /// @dev Tracking nonces for mintWithSig to prevent replay attacks
    mapping(address => uint256) public mintNonces;

    /// @dev EIP-712 typehash for gasless minting
    bytes32 public constant MINT_TYPEHASH =
        keccak256("Mint(address to,uint256 amount,uint256 nonce,uint256 deadline)");

    /// @param initialSupply Initial token supply in wei (set to 0 for no initial mint)
    constructor(uint256 initialSupply) 
        ERC20("Rain Cloud Protocol", "RCP") 
        ERC20Permit("Rain Cloud Protocol") 
    {
        if (initialSupply > 0) {
            _mint(msg.sender, initialSupply);
        }
    }

    // ============== Gasless Mint ==============
    /// @notice Mint tokens via owner's EIP-712 signature
    /// @dev Relayer submits transaction, recipient pays no gas
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
    ) external {
        require(block.timestamp <= deadline, "RCP: Signature expired");
        require(to != address(0), "RCP: Invalid recipient");

        uint256 nonce = mintNonces[to];
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                MINT_TYPEHASH,
                to,
                amount,
                nonce,
                deadline
            ))
        );

        require(digest.recover(v, r, s) == owner(), "RCP: Invalid signature");
        
        mintNonces[to] = nonce + 1; // Prevent replay attacks
        _mint(to, amount);
    }

    // ============== Owner Functions ==============
    /// @notice Standard mint function (owner only)
    /// @dev No supply cap - owner can mint as needed
    function mint(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "RCP: Invalid recipient");
        _mint(to, amount);
    }

    // ============== Burn Functions ==============
    /// @notice Burn tokens from caller's balance
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    /// @notice Burn tokens from another account using allowance
    function burnFrom(address account, uint256 amount) external {
        _spendAllowance(account, msg.sender, amount);
        _burn(account, amount);
    }

    // ============== Utility Functions ==============
    /// @notice Convert totalSupply from wei to token units
    /// @return Supply in whole token units (1 RCP = 1e18 wei)
    function totalSupplyInTokens() external view returns (uint256) {
        return totalSupply() / (10 ** decimals());
    }

    // ============== Overrides ==============
    // Explicit overrides for clarity
    function _afterTokenTransfer(address from, address to, uint256 amount)
        internal
        override(ERC20)
    {
        super._afterTokenTransfer(from, to, amount);
    }

    function _burn(address account, uint256 amount) 
        internal 
        override(ERC20) 
    {
        super._burn(account, amount);
    }

    function _mint(address account, uint256 amount) 
        internal 
        override(ERC20) 
    {
        super._mint(account, amount);
    }
}
