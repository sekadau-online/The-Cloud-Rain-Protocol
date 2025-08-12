// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// OpenZeppelin imports
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title Rain Cloud Protocol (RCP)
/// @notice ERC20 token pegged 1:1 with IDR (optional initial supply), uncapped (no MAX), with gasless minting via EIP-712
contract RainCloudProtocol is ERC20, ERC20Permit, Ownable {
    using ECDSA for bytes32;

    /// @dev Separate nonce tracking for mintWithSig to prevent replay attacks
    mapping(address => uint256) public mintNonces;

    /// @dev EIP-712 typehash for gasless minting
    bytes32 public constant MINT_TYPEHASH =
        keccak256("Mint(address to,uint256 amount,uint256 nonce,uint256 deadline)");

    /// @param initialSupply Initial token supply in wei (use 0 if you don't want initial mint)
    constructor(uint256 initialSupply) 
        ERC20("Rain Cloud Protocol", "RCP") 
        ERC20Permit("Rain Cloud Protocol") 
    {
        if (initialSupply > 0) {
            _mint(msg.sender, initialSupply);
        }
    }

    // ============== Gasless Mint ==============
    /// @notice Mint tokens via owner's EIP-712 signature (relayer submits tx and pays gas)
    /// @param to Recipient address
    /// @param amount Amount to mint (in wei)
    /// @param deadline Signature expiration timestamp (unix)
    /// @param v,r,s Signature components from owner's signature
    function mintWithSig(
        address to,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "RCP: signature expired");

        // read nonce first, then increment only after successful signature verification
        uint256 nonce = mintNonces[to];

        bytes32 structHash = keccak256(abi.encode(
            MINT_TYPEHASH,
            to,
            amount,
            nonce,
            deadline
        ));

        bytes32 hash = _hashTypedDataV4(structHash); // provided by EIP712 via ERC20Permit
        address signer = hash.recover(v, r, s);
        require(signer == owner(), "RCP: invalid signature");

        // increment nonce (prevents replays)
        mintNonces[to] = nonce + 1;

        _mint(to, amount);
    }

    // ============== Owner Functions ==============
    /// @notice Standard mint function (owner only). Because supply is uncapped, owner can mint more as needed.
    function mint(address to, uint256 amount) external onlyOwner {
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

    // ============== Read helpers ==============
    /// @notice Return totalSupply in token units (not wei). Example: if decimals=18 and totalSupply=1e27, this returns 1e9.
    function totalSupplyTokens() external view returns (uint256) {
        return totalSupply() / (10 ** decimals());
    }

    // ============== Overrides ==============
    function _afterTokenTransfer(address from, address to, uint256 amount)
        internal
        override(ERC20)
    {
        super._afterTokenTransfer(from, to, amount);
    }

    function _burn(address account, uint256 amount) internal override(ERC20) {
        super._burn(account, amount);
    }

    function _mint(address account, uint256 amount) internal override(ERC20) {
        super._mint(account, amount);
    }
}
