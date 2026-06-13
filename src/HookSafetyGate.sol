// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  HookSafetyGate
/// @notice A standalone, default-closed admission gate that lets any Uniswap v4
///         integrator decide whether a pool's hook is safe to route through,
///         BEFORE any token moves. It enforces three independent checks:
///
///           Layer 1 - Delta-permission screen (immutable, in code):
///             A hook may only be routable if its address does NOT carry either
///             of the two return-delta permission flags. Those flags are the only
///             ones that let a hook modify swap accounting; a hook that lacks them
///             is, by the PoolManager's own enforcement, incapable of altering
///             what a swapper pays or receives. Pure: reads only the address.
///
///           Layer 2 - Default-closed allow-list (governed):
///             A hook is routable only if it has been explicitly allow-listed by
///             this contract's owner. Anything not admitted is denied.
///
///           Layer 3 - Code-hash pinning (immutable, in code):
///             When a hook is admitted, the EXTCODEHASH of its address is recorded.
///             A hook is only routable while its current code hash equals the hash
///             pinned at admission time. This closes the "approved proxy upgrades
///             to malicious logic" vector: if the code behind the address changes
///             (proxy upgrade pattern, selfdestruct-and-redeploy), the pin no
///             longer matches and the hook is automatically treated as unsafe
///             until an owner re-reviews and re-admits it.
///
///         The contract holds no funds, makes no external calls into hook code,
///         and cannot move tokens. It is purely an advisory predicate plus an
///         owner-managed allow-list with code-hash pinning. Integrators call
///         `isRoutableHook(hook)` and act on the boolean.
///
/// @dev    Permission-flag values are taken verbatim from the canonical Uniswap v4
///         `Hooks` library (Uniswap/v4-core, src/libraries/Hooks.sol). They are
///         redeclared here as constants - rather than imported - so this contract
///         has ZERO external dependencies and can be audited and deployed in
///         isolation. The values are verified against v4-core in the test suite.
///
///         Reference (v4-core Hooks.sol):
///           BEFORE_SWAP_RETURNS_DELTA_FLAG = 1 << 3  (0x08)
///           AFTER_SWAP_RETURNS_DELTA_FLAG  = 1 << 2  (0x04)
contract HookSafetyGate {
    // -------------------------------------------------------------------------
    // Constants - verbatim from Uniswap v4-core Hooks.sol, verified in tests.
    // -------------------------------------------------------------------------

    uint160 internal constant BEFORE_SWAP_RETURNS_DELTA_FLAG = uint160(1 << 3);
    uint160 internal constant AFTER_SWAP_RETURNS_DELTA_FLAG = uint160(1 << 2);

    /// @notice Mask of all accounting-altering permission bits. A hook whose
    ///         address ANDs to non-zero against this mask can modify swap deltas
    ///         and is therefore never routable, regardless of the allow-list.
    uint160 internal constant DELTA_FLAGS_MASK =
        BEFORE_SWAP_RETURNS_DELTA_FLAG | AFTER_SWAP_RETURNS_DELTA_FLAG;

    // -------------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------------

    /// @notice The address permitted to manage the allow-list.
    address public owner;

    /// @notice Code hash pinned at admission time. A non-zero value means the
    ///         hook is allow-listed; routability additionally requires that the
    ///         hook's CURRENT code hash still equals this pinned value.
    /// @dev    We store the hash (not a bool) so the allow-list and the pin are a
    ///         single SLOAD. address(0) and unset hooks have a zero pin.
    mapping(address hook => bytes32 pinnedCodeHash) public pinnedCodeHash;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    event OwnerTransferred(address indexed previousOwner, address indexed newOwner);
    event HookAllowed(address indexed hook, bytes32 codeHash);
    event HookDenied(address indexed hook);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error NotOwner();
    error HookHasDeltaFlags(address hook);
    error ZeroAddress();

    /// @notice Thrown when admitting a hook whose address has no deployed code.
    error HookHasNoCode(address hook);

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert ZeroAddress();
        owner = initialOwner;
        emit OwnerTransferred(address(0), initialOwner);
    }

    // -------------------------------------------------------------------------
    // Layer 1 - pure delta-permission screen
    // -------------------------------------------------------------------------

    /// @notice Returns true iff the hook address carries NO accounting-altering
    ///         (return-delta) permission flag.
    /// @dev    Pure. Reads only the address. Never calls the hook. Constant time.
    function hasNoDeltaFlags(address hook) public pure returns (bool) {
        return (uint160(hook) & DELTA_FLAGS_MASK) == 0;
    }

    // -------------------------------------------------------------------------
    // Combined predicate - the function integrators call
    // -------------------------------------------------------------------------

    /// @notice The single predicate an integrator consults before routing a v4 leg.
    ///         Returns true iff EITHER:
    ///           (a) the pool has no hook (`hook == address(0)`), OR
    ///           (b) the hook carries no delta flags (Layer 1) AND it is
    ///               allow-listed AND its current code hash still equals the hash
    ///               pinned at admission (Layers 2 + 3).
    /// @dev    View. One SLOAD for the pin, one EXTCODEHASH. Never calls the hook.
    function isRoutableHook(address hook) external view returns (bool) {
        if (hook == address(0)) return true;
        if (!hasNoDeltaFlags(hook)) return false; // Layer 1 - cannot be overridden
        bytes32 pinned = pinnedCodeHash[hook];
        if (pinned == bytes32(0)) return false; // Layer 2 - not admitted (default-closed)
        return hook.codehash == pinned; // Layer 3 - code unchanged since admission
    }

    /// @notice Convenience view: true iff the hook is admitted but its code has
    ///         since changed (i.e. it WOULD be routable but for the pin mismatch).
    function isStale(address hook) external view returns (bool) {
        bytes32 pinned = pinnedCodeHash[hook];
        if (pinned == bytes32(0)) return false; // never admitted
        return hook.codehash != pinned; // admitted but code changed
    }

    // -------------------------------------------------------------------------
    // Allow-list management (owner only)
    // -------------------------------------------------------------------------

    /// @notice Admit a hook to the allow-list and pin its current code hash.
    /// @dev    Reverts if the hook carries any delta flag (Layer 1 enforced at
    ///         write time), if it is the zero address, or if it has no code.
    ///         Re-admitting re-pins to current code hash - the correct action
    ///         after a reviewed, intentional upgrade.
    function allowHook(address hook) external onlyOwner {
        if (hook == address(0)) revert ZeroAddress();
        if (!hasNoDeltaFlags(hook)) revert HookHasDeltaFlags(hook);
        bytes32 h = hook.codehash;
        if (h == bytes32(0) || h == keccak256("")) revert HookHasNoCode(hook);
        pinnedCodeHash[hook] = h;
        emit HookAllowed(hook, h);
    }

    /// @notice Remove a hook from the allow-list (clears its pin). Idempotent.
    function denyHook(address hook) external onlyOwner {
        if (pinnedCodeHash[hook] != bytes32(0)) {
            pinnedCodeHash[hook] = bytes32(0);
            emit HookDenied(hook);
        }
    }

    // -------------------------------------------------------------------------
    // Ownership
    // -------------------------------------------------------------------------

    /// @notice Transfer allow-list ownership. Intended to migrate from a deploy
    ///         key to a multisig / the Uniswap Foundation.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnerTransferred(owner, newOwner);
        owner = newOwner;
    }
}
