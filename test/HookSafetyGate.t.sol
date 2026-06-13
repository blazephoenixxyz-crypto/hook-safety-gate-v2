// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {HookSafetyGate} from "../src/HookSafetyGate.sol";

/// @dev Minimal contracts used only to give test hook addresses real code,
///      and to swap that code to simulate a proxy upgrade / redeploy.
contract BenignHookCode {
    function ping() external pure returns (uint256) { return 1; }
}

contract MaliciousHookCode {
    function ping() external pure returns (uint256) { return 666; }
    function steal() external pure returns (bool) { return true; }
}

contract HookSafetyGateTest is Test {
    HookSafetyGate internal gate;

    address internal owner = address(0xA11CE);
    address internal stranger = address(0xBEEF);

    uint160 internal constant BEFORE_SWAP_RETURNS_DELTA_FLAG = uint160(1 << 3); // 0x08
    uint160 internal constant AFTER_SWAP_RETURNS_DELTA_FLAG = uint160(1 << 2);  // 0x04

    // High base with the two delta bits clear; low 16 bits zero so flag bits are clear.
    uint160 internal constant BASE = uint160(0xaBCd) << 16;

    function _hookWith(uint160 flagBits) internal pure returns (address) {
        return address(BASE | flagBits);
    }

    function setUp() public {
        vm.prank(owner);
        gate = new HookSafetyGate(owner);
    }

    // --- helper: give an address real code (benign) ---
    function _deployBenignAt(address where) internal {
        BenignHookCode c = new BenignHookCode();
        vm.etch(where, address(c).code);
    }

    function _deployMaliciousAt(address where) internal {
        MaliciousHookCode c = new MaliciousHookCode();
        vm.etch(where, address(c).code);
    }

    // -------------------------------------------------------------------------
    // Constructor / ownership
    // -------------------------------------------------------------------------

    function test_constructor_setsOwner() public view {
        assertEq(gate.owner(), owner);
    }

    function test_constructor_revertsOnZeroOwner() public {
        vm.expectRevert(HookSafetyGate.ZeroAddress.selector);
        new HookSafetyGate(address(0));
    }

    // -------------------------------------------------------------------------
    // CRITICAL: constants match canonical Uniswap v4-core Hooks.sol
    // -------------------------------------------------------------------------

    function test_constants_matchV4Core() public pure {
        assertEq(BEFORE_SWAP_RETURNS_DELTA_FLAG, uint160(8));
        assertEq(AFTER_SWAP_RETURNS_DELTA_FLAG, uint160(4));
    }

    // -------------------------------------------------------------------------
    // Layer 1 - delta-permission screen (pure)
    // -------------------------------------------------------------------------

    function test_layer1_beforeSwapDelta_isNotClean() public view {
        assertFalse(gate.hasNoDeltaFlags(_hookWith(BEFORE_SWAP_RETURNS_DELTA_FLAG)));
    }

    function test_layer1_afterSwapDelta_isNotClean() public view {
        assertFalse(gate.hasNoDeltaFlags(_hookWith(AFTER_SWAP_RETURNS_DELTA_FLAG)));
    }

    function test_layer1_bothDeltaFlags_isNotClean() public view {
        assertFalse(gate.hasNoDeltaFlags(_hookWith(BEFORE_SWAP_RETURNS_DELTA_FLAG | AFTER_SWAP_RETURNS_DELTA_FLAG)));
    }

    function test_layer1_noDeltaFlags_isClean() public view {
        assertTrue(gate.hasNoDeltaFlags(_hookWith(0)));
    }

    function test_layer1_zeroAddress_isClean() public view {
        assertTrue(gate.hasNoDeltaFlags(address(0)));
    }

    // -------------------------------------------------------------------------
    // isRoutableHook - combined predicate
    // -------------------------------------------------------------------------

    function test_routable_hooklessPool_alwaysRoutable() public view {
        assertTrue(gate.isRoutableHook(address(0)));
    }

    function test_routable_cleanHookNotAllowlisted_isDenied() public {
        address hook = _hookWith(0);
        _deployBenignAt(hook);
        assertFalse(gate.isRoutableHook(hook)); // default-closed
    }

    function test_routable_cleanHookAllowlisted_isRoutable() public {
        address hook = _hookWith(0);
        _deployBenignAt(hook);
        vm.prank(owner);
        gate.allowHook(hook);
        assertTrue(gate.isRoutableHook(hook));
    }

    function test_routable_deltaHookNeverRoutable() public {
        address hook = _hookWith(BEFORE_SWAP_RETURNS_DELTA_FLAG);
        _deployBenignAt(hook);
        assertFalse(gate.isRoutableHook(hook));
    }

    function test_routable_afterDeny_returnsFalse() public {
        address hook = _hookWith(0);
        _deployBenignAt(hook);
        vm.startPrank(owner);
        gate.allowHook(hook);
        assertTrue(gate.isRoutableHook(hook));
        gate.denyHook(hook);
        vm.stopPrank();
        assertFalse(gate.isRoutableHook(hook));
    }

    // -------------------------------------------------------------------------
    // Layer 3 - CODE-HASH PINNING (the new, decisive behaviour)
    // -------------------------------------------------------------------------

    /// @notice The headline guarantee: a hook admitted while benign becomes
    ///         NON-routable the instant its code changes to something else
    ///         (proxy upgrade / selfdestruct-redeploy), with no owner action.
    function test_layer3_codeChangeAfterAdmission_makesHookUnroutable() public {
        address hook = _hookWith(0);
        _deployBenignAt(hook);

        vm.prank(owner);
        gate.allowHook(hook);
        assertTrue(gate.isRoutableHook(hook), "should be routable while benign");

        // Attacker swaps the code behind the same address to malicious logic.
        _deployMaliciousAt(hook);

        assertFalse(gate.isRoutableHook(hook), "must be blocked after code change");
        assertTrue(gate.isStale(hook), "should report stale (admitted but changed)");
    }

    /// @notice After a reviewed, intentional upgrade the owner can re-admit,
    ///         which re-pins to the new code hash and restores routability.
    function test_layer3_reAdmitAfterUpgrade_repinsAndRestores() public {
        address hook = _hookWith(0);
        _deployBenignAt(hook);
        vm.prank(owner);
        gate.allowHook(hook);

        _deployMaliciousAt(hook);
        assertFalse(gate.isRoutableHook(hook));

        // Owner reviews the new code and decides to re-admit it.
        vm.prank(owner);
        gate.allowHook(hook);
        assertTrue(gate.isRoutableHook(hook), "re-admission re-pins to new code hash");
        assertFalse(gate.isStale(hook));
    }

    function test_layer3_isStale_falseForNeverAdmitted() public {
        address hook = _hookWith(0);
        _deployBenignAt(hook);
        assertFalse(gate.isStale(hook));
    }

    // -------------------------------------------------------------------------
    // Allow-list management
    // -------------------------------------------------------------------------

    function test_allowHook_revertsForDeltaFlaggedHook() public {
        address hook = _hookWith(AFTER_SWAP_RETURNS_DELTA_FLAG);
        _deployBenignAt(hook);
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(HookSafetyGate.HookHasDeltaFlags.selector, hook));
        gate.allowHook(hook);
    }

    function test_allowHook_revertsForZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(HookSafetyGate.ZeroAddress.selector);
        gate.allowHook(address(0));
    }

    function test_allowHook_revertsForNoCode() public {
        address hook = _hookWith(0); // no code etched
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(HookSafetyGate.HookHasNoCode.selector, hook));
        gate.allowHook(hook);
    }

    function test_allowHook_onlyOwner() public {
        address hook = _hookWith(0);
        _deployBenignAt(hook);
        vm.prank(stranger);
        vm.expectRevert(HookSafetyGate.NotOwner.selector);
        gate.allowHook(hook);
    }

    function test_denyHook_onlyOwner() public {
        address hook = _hookWith(0);
        vm.prank(stranger);
        vm.expectRevert(HookSafetyGate.NotOwner.selector);
        gate.denyHook(hook);
    }

    function test_allowHook_pinsCodeHashAndEmits() public {
        address hook = _hookWith(0);
        _deployBenignAt(hook);
        bytes32 expected = hook.codehash;
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit HookSafetyGate.HookAllowed(hook, expected);
        gate.allowHook(hook);
        assertEq(gate.pinnedCodeHash(hook), expected);
    }

    // -------------------------------------------------------------------------
    // Ownership transfer
    // -------------------------------------------------------------------------

    function test_transferOwnership() public {
        vm.prank(owner);
        gate.transferOwnership(stranger);
        assertEq(gate.owner(), stranger);
    }

    function test_transferOwnership_revertsOnZero() public {
        vm.prank(owner);
        vm.expectRevert(HookSafetyGate.ZeroAddress.selector);
        gate.transferOwnership(address(0));
    }

    function test_transferOwnership_onlyOwner() public {
        vm.prank(stranger);
        vm.expectRevert(HookSafetyGate.NotOwner.selector);
        gate.transferOwnership(stranger);
    }

    // -------------------------------------------------------------------------
    // Fuzz - a delta-flagged hook is never routable and never allow-listable.
    // -------------------------------------------------------------------------

    function testFuzz_deltaFlaggedHookNeverRoutable(address hook) public {
        vm.assume(hook != address(0));
        uint160 bits = uint160(hook) & DELTA_FLAGS_MASK_LOCAL();
        if (bits != 0) {
            _deployBenignAt(hook);
            assertFalse(gate.isRoutableHook(hook));
            vm.prank(owner);
            vm.expectRevert(abi.encodeWithSelector(HookSafetyGate.HookHasDeltaFlags.selector, hook));
            gate.allowHook(hook);
        }
    }

    function DELTA_FLAGS_MASK_LOCAL() internal pure returns (uint160) {
        return BEFORE_SWAP_RETURNS_DELTA_FLAG | AFTER_SWAP_RETURNS_DELTA_FLAG;
    }
}
