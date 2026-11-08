// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.38;

import {Test} from "forge-std/Test.sol";
import {ThreatReportRegistry as R} from "../src/ThreatReportRegistry.sol";

contract ThreatReportRegistryTest is Test {
    R internal reg;
    address internal owner = address(this);
    address internal reporter = makeAddr("reporter");
    address internal reporter2 = makeAddr("reporter2");
    address internal reviewer = makeAddr("reviewer");
    address internal stranger = makeAddr("stranger");

    // Values from docs/commitment-vectors.json.
    bytes32 internal constant ID = 0xefacb7938499ae4b0a14eb00d995022aae753863306a67b24c60d3d131ba59df;
    bytes32 internal constant C0 = 0x354eb41ec43a25cef41b6a5c0cbad3caaeccce534a0a72c5639965df6eab2e7d;
    bytes32 internal constant C1 = 0xbd344a60dacde8bfa66a10e333cfa829c12230b352fa45940eccf6f9bb6dfe78;
    bytes32 internal constant C2 = keccak256("c2");
    bytes32 internal constant NOTE = keccak256("review note");

    event ReportRegistered(bytes32 indexed reportId, address indexed author, bytes32 commitment, uint8 classification);
    event ReportRevised(bytes32 indexed reportId, uint256 indexed revision, bytes32 commitment, uint8 classification);
    event StatusChanged(bytes32 indexed reportId, R.Status status, address indexed by, bytes32 noteHash);
    event ReporterSet(address indexed account, bool allowed);
    event ReviewerSet(address indexed account, bool allowed);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        reg = new R();
        reg.setReporter(reporter, true);
        reg.setReporter(reporter2, true);
        reg.setReviewer(reviewer, true);
        vm.warp(1_793_000_000);
    }

    function _register() internal {
        vm.prank(reporter);
        reg.register(ID, C0, 3);
    }

    function test_HappyPath_RegisterReviseSetStatus() public {
        _register();
        assertEq(reg.revisionCount(ID), 1);
        assertEq(reg.reportAuthor(ID), reporter);
        assertTrue(reg.commitmentUsed(C0));
        assertEq(uint8(reg.currentStatus(ID)), uint8(R.Status.Pending));
        R.Revision memory r0 = reg.getRevision(ID, 0);
        assertEq(r0.commitment, C0);
        assertEq(r0.classification, 3);
        assertEq(r0.timestamp, 1_793_000_000);
        assertEq(r0.author, reporter);

        vm.warp(1_793_000_100);
        vm.prank(reporter);
        reg.revise(ID, 1, C1, 4);
        assertEq(reg.revisionCount(ID), 2);
        R.Revision memory r1 = reg.getRevision(ID, 1);
        assertEq(r1.commitment, C1);
        assertEq(r1.classification, 4);
        assertEq(r1.timestamp, 1_793_000_100);
        assertEq(reg.statusCount(ID), 0, "no reset entry when already Pending");

        vm.prank(reviewer);
        reg.setStatus(ID, R.Status.Validated, NOTE);
        assertEq(uint8(reg.currentStatus(ID)), uint8(R.Status.Validated));
        assertEq(reg.statusCount(ID), 1);
        R.StatusChange memory s = reg.getStatusChange(ID, 0);
        assertEq(uint8(s.status), uint8(R.Status.Validated));
        assertEq(s.by, reviewer);
        assertEq(s.noteHash, NOTE);
        assertEq(s.timestamp, 1_793_000_100);
    }

    function test_RevertWhen_RegisterByNonReporter() public {
        vm.prank(stranger);
        vm.expectRevert(R.NotReporter.selector);
        reg.register(ID, C0, 3);
    }

    function test_RevertWhen_RevokedReporterRegisters() public {
        reg.setReporter(reporter, false);
        vm.prank(reporter);
        vm.expectRevert(R.NotReporter.selector);
        reg.register(ID, C0, 3);
    }

    function test_RevertWhen_ReviseByOtherReporter() public {
        _register();
        vm.prank(reporter2);
        vm.expectRevert(R.NotAuthor.selector);
        reg.revise(ID, 1, C1, 3);
    }

    function test_RevertWhen_ReviseByNonReporter() public {
        _register();
        vm.prank(stranger);
        vm.expectRevert(R.NotReporter.selector);
        reg.revise(ID, 1, C1, 3);
    }

    function test_RevertWhen_ReviseUnknownReport() public {
        vm.prank(reporter);
        vm.expectRevert(abi.encodeWithSelector(R.ReportNotFound.selector, ID));
        reg.revise(ID, 0, C1, 3);
    }

    function test_RevertWhen_ReviseOutOfOrder() public {
        _register();
        vm.startPrank(reporter);
        vm.expectRevert(abi.encodeWithSelector(R.RevisionMismatch.selector, 0, 1));
        reg.revise(ID, 0, C1, 3);
        vm.expectRevert(abi.encodeWithSelector(R.RevisionMismatch.selector, 2, 1));
        reg.revise(ID, 2, C1, 3);
        reg.revise(ID, 1, C1, 3);
        vm.expectRevert(abi.encodeWithSelector(R.RevisionMismatch.selector, 1, 2));
        reg.revise(ID, 1, C2, 3); // stale writer retrying the same slot
        vm.stopPrank();
    }

    function test_RevertWhen_DuplicateReportId() public {
        _register();
        vm.prank(reporter2);
        vm.expectRevert(abi.encodeWithSelector(R.ReportAlreadyExists.selector, ID));
        reg.register(ID, C1, 3);
    }

    function test_RevertWhen_CommitmentReused() public {
        _register();
        vm.startPrank(reporter);
        vm.expectRevert(abi.encodeWithSelector(R.CommitmentAlreadyUsed.selector, C0));
        reg.register(keccak256("other report"), C0, 3);
        vm.expectRevert(abi.encodeWithSelector(R.CommitmentAlreadyUsed.selector, C0));
        reg.revise(ID, 1, C0, 3);
        vm.stopPrank();
    }

    function test_RevertWhen_ZeroCommitment() public {
        vm.prank(reporter);
        vm.expectRevert(R.ZeroCommitment.selector);
        reg.register(ID, bytes32(0), 3);
        _register();
        vm.prank(reporter);
        vm.expectRevert(R.ZeroCommitment.selector);
        reg.revise(ID, 1, bytes32(0), 3);
    }

    function test_RevertWhen_BadClassification() public {
        vm.prank(reporter);
        vm.expectRevert(abi.encodeWithSelector(R.InvalidClassification.selector, 5));
        reg.register(ID, C0, 5);
        vm.prank(reporter);
        reg.register(ID, C0, 4); // boundary is allowed
        vm.prank(reporter);
        vm.expectRevert(abi.encodeWithSelector(R.InvalidClassification.selector, 255));
        reg.revise(ID, 1, C1, 255);
    }

    function test_RevertWhen_ReviewerSelfReviews() public {
        reg.setReporter(reviewer, true); // one account holding both roles
        vm.prank(reviewer);
        reg.register(ID, C0, 3);
        vm.prank(reviewer);
        vm.expectRevert(R.SelfReview.selector);
        reg.setStatus(ID, R.Status.Validated, NOTE);
    }

    function test_RevertWhen_NonReviewerSetsStatus() public {
        _register();
        vm.prank(stranger);
        vm.expectRevert(R.NotReviewer.selector);
        reg.setStatus(ID, R.Status.Validated, NOTE);
        vm.prank(reporter);
        vm.expectRevert(R.NotReviewer.selector);
        reg.setStatus(ID, R.Status.Validated, NOTE);
    }

    function test_RevertWhen_SetStatusUnknownReport() public {
        vm.prank(reviewer);
        vm.expectRevert(abi.encodeWithSelector(R.ReportNotFound.selector, ID));
        reg.setStatus(ID, R.Status.Disputed, NOTE);
    }

    function test_ReviseResetsStatusToPending() public {
        _register();
        vm.prank(reviewer);
        reg.setStatus(ID, R.Status.Validated, NOTE);

        vm.expectEmit(true, true, true, true, address(reg));
        emit StatusChanged(ID, R.Status.Pending, reporter, bytes32(0));
        vm.prank(reporter);
        reg.revise(ID, 1, C1, 3);

        assertEq(uint8(reg.currentStatus(ID)), uint8(R.Status.Pending));
        assertEq(reg.statusCount(ID), 2);
        R.StatusChange memory reset = reg.getStatusChange(ID, 1);
        assertEq(uint8(reset.status), uint8(R.Status.Pending));
        assertEq(reset.by, reporter);
        // The earlier review is still in the history.
        assertEq(uint8(reg.getStatusChange(ID, 0).status), uint8(R.Status.Validated));
    }

    function test_HistoryIsAppendOnly() public {
        _register();
        R.Revision memory before0 = reg.getRevision(ID, 0);
        vm.prank(reviewer);
        reg.setStatus(ID, R.Status.Disputed, NOTE);
        vm.warp(block.timestamp + 60);
        vm.startPrank(reporter);
        reg.revise(ID, 1, C1, 2);
        reg.revise(ID, 2, C2, 1);
        vm.stopPrank();

        R.Revision memory after0 = reg.getRevision(ID, 0);
        assertEq(after0.commitment, before0.commitment);
        assertEq(after0.classification, before0.classification);
        assertEq(after0.timestamp, before0.timestamp);
        assertEq(after0.author, before0.author);
        assertEq(reg.getRevision(ID, 1).commitment, C1);
        assertEq(reg.getRevision(ID, 2).commitment, C2);
        assertEq(reg.revisionCount(ID), 3);
        assertTrue(reg.commitmentUsed(C0) && reg.commitmentUsed(C1) && reg.commitmentUsed(C2));
        R.StatusChange memory s0 = reg.getStatusChange(ID, 0);
        assertEq(uint8(s0.status), uint8(R.Status.Disputed));
        assertEq(s0.noteHash, NOTE);

        vm.expectRevert(abi.encodeWithSelector(R.IndexOutOfRange.selector, 3, 3));
        reg.getRevision(ID, 3);
        vm.expectRevert(abi.encodeWithSelector(R.IndexOutOfRange.selector, 2, 2));
        reg.getStatusChange(ID, 2);
    }

    function test_UnknownReportViews() public {
        assertEq(reg.revisionCount(ID), 0);
        assertEq(reg.statusCount(ID), 0);
        assertEq(reg.reportAuthor(ID), address(0));
        vm.expectRevert(abi.encodeWithSelector(R.ReportNotFound.selector, ID));
        reg.currentStatus(ID);
        vm.expectRevert(abi.encodeWithSelector(R.IndexOutOfRange.selector, 0, 0));
        reg.getRevision(ID, 0);
    }

    function test_OwnershipTwoStep() public {
        address next = makeAddr("next");
        vm.prank(stranger);
        vm.expectRevert(R.NotOwner.selector);
        reg.transferOwnership(next);

        vm.expectEmit(true, true, false, false, address(reg));
        emit OwnershipTransferStarted(owner, next);
        reg.transferOwnership(next);
        assertEq(reg.owner(), owner, "owner unchanged until accepted");
        assertEq(reg.pendingOwner(), next);

        vm.prank(stranger);
        vm.expectRevert(R.NotPendingOwner.selector);
        reg.acceptOwnership();

        vm.expectEmit(true, true, false, false, address(reg));
        emit OwnershipTransferred(owner, next);
        vm.prank(next);
        reg.acceptOwnership();
        assertEq(reg.owner(), next);
        assertEq(reg.pendingOwner(), address(0));

        vm.expectRevert(R.NotOwner.selector);
        reg.setReporter(stranger, true);
        vm.prank(next);
        reg.setReporter(stranger, true);
        assertTrue(reg.isReporter(stranger));
    }

    function test_OwnershipTransferCanBeCancelled() public {
        address next = makeAddr("next");
        reg.transferOwnership(next);
        reg.transferOwnership(address(0));
        vm.prank(next);
        vm.expectRevert(R.NotPendingOwner.selector);
        reg.acceptOwnership();
        assertEq(reg.owner(), owner);
    }

    function test_RevertWhen_RoleAdminByNonOwnerOrZero() public {
        vm.startPrank(stranger);
        vm.expectRevert(R.NotOwner.selector);
        reg.setReporter(stranger, true);
        vm.expectRevert(R.NotOwner.selector);
        reg.setReviewer(stranger, true);
        vm.stopPrank();
        vm.expectRevert(R.ZeroAddress.selector);
        reg.setReporter(address(0), true);
        vm.expectRevert(R.ZeroAddress.selector);
        reg.setReviewer(address(0), true);
    }

    function test_EventsEmitted() public {
        vm.expectEmit(true, false, false, true, address(reg));
        emit ReporterSet(stranger, true);
        reg.setReporter(stranger, true);
        vm.expectEmit(true, false, false, true, address(reg));
        emit ReviewerSet(stranger, false);
        reg.setReviewer(stranger, false);

        vm.expectEmit(true, true, false, true, address(reg));
        emit ReportRegistered(ID, reporter, C0, 3);
        _register();

        vm.expectEmit(true, true, false, true, address(reg));
        emit ReportRevised(ID, 1, C1, 2);
        vm.prank(reporter);
        reg.revise(ID, 1, C1, 2);

        vm.expectEmit(true, true, false, true, address(reg));
        emit StatusChanged(ID, R.Status.Retracted, reviewer, NOTE);
        vm.prank(reviewer);
        reg.setStatus(ID, R.Status.Retracted, NOTE);
    }

    function testFuzz_ClassificationBound(uint8 classification) public {
        vm.prank(reporter);
        if (classification > 4) {
            vm.expectRevert(abi.encodeWithSelector(R.InvalidClassification.selector, classification));
        }
        reg.register(ID, C0, classification);
    }
}
