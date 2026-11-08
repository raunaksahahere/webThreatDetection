// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// @title ThreatReportRegistry
/// @notice Append-only registry of salted SHA-256 commitments to off-chain threat reports
///         (wtd.commitment.v1). Only hashes and a classification code are stored: no URLs,
///         message text, indicators or personal data. A matching commitment shows the document
///         is unchanged since it was anchored under these rules; it is not proof the report is true.
contract ThreatReportRegistry {
    enum Status { Pending, Validated, Disputed, Retracted }

    struct Revision { bytes32 commitment; uint8 classification; uint64 timestamp; address author; }
    struct StatusChange { Status status; uint64 timestamp; address by; bytes32 noteHash; }

    /// @notice Highest classification code: 0 Inconclusive, 1 Low Risk, 2 Suspicious, 3 High Risk, 4 Confirmed Malicious.
    uint8 public constant MAX_CLASSIFICATION = 4;

    address public owner;
    address public pendingOwner;
    mapping(address => bool) public isReporter;
    mapping(address => bool) public isReviewer;
    /// @notice Original author of a report, or address(0) if the report does not exist.
    mapping(bytes32 => address) public reportAuthor;
    /// @notice True once a commitment has been used by any revision of any report.
    mapping(bytes32 => bool) public commitmentUsed;
    mapping(bytes32 => Revision[]) private _revisions;
    mapping(bytes32 => StatusChange[]) private _statuses;

    event ReportRegistered(bytes32 indexed reportId, address indexed author, bytes32 commitment, uint8 classification);
    event ReportRevised(bytes32 indexed reportId, uint256 indexed revision, bytes32 commitment, uint8 classification);
    event StatusChanged(bytes32 indexed reportId, Status status, address indexed by, bytes32 noteHash);
    event ReporterSet(address indexed account, bool allowed);
    event ReviewerSet(address indexed account, bool allowed);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotPendingOwner();
    error NotReporter();
    error NotReviewer();
    error NotAuthor();
    error SelfReview();
    error ZeroAddress();
    error ZeroCommitment();
    error CommitmentAlreadyUsed(bytes32 commitment);
    error InvalidClassification(uint8 classification);
    error ReportAlreadyExists(bytes32 reportId);
    error ReportNotFound(bytes32 reportId);
    error RevisionMismatch(uint256 expected, uint256 actual);
    error IndexOutOfRange(uint256 index, uint256 length);

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwner(); _; }
    modifier onlyReporter() { if (!isReporter[msg.sender]) revert NotReporter(); _; }
    modifier onlyReviewer() { if (!isReviewer[msg.sender]) revert NotReviewer(); _; }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Anchor revision 0 of a new report. Caller becomes the report's author.
    /// @param reportId sha256("wtd.report-id.v1:" + report_id); must not exist yet.
    /// @param commitment sha256(JCS(envelope)); non-zero and never used before.
    /// @param classification Classification code, at most MAX_CLASSIFICATION.
    function register(bytes32 reportId, bytes32 commitment, uint8 classification) external onlyReporter {
        if (reportAuthor[reportId] != address(0)) revert ReportAlreadyExists(reportId);
        _append(reportId, commitment, classification);
        reportAuthor[reportId] = msg.sender;
        emit ReportRegistered(reportId, msg.sender, commitment, classification);
    }

    /// @notice Append a new revision to a report. Only its original author (still a reporter) may revise.
    ///         A non-Pending status is reset to Pending by appending a status entry.
    /// @param expectedRevision Must equal revisionCount(reportId); guards against out-of-order writes.
    function revise(bytes32 reportId, uint256 expectedRevision, bytes32 commitment, uint8 classification)
        external
        onlyReporter
    {
        address author = reportAuthor[reportId];
        if (author == address(0)) revert ReportNotFound(reportId);
        if (author != msg.sender) revert NotAuthor();
        uint256 count = _revisions[reportId].length;
        if (expectedRevision != count) revert RevisionMismatch(expectedRevision, count);
        _append(reportId, commitment, classification);
        emit ReportRevised(reportId, count, commitment, classification);
        if (currentStatus(reportId) != Status.Pending) _pushStatus(reportId, Status.Pending, bytes32(0));
    }

    /// @notice Record a review outcome. Reviewers cannot review reports they authored.
    /// @param noteHash Hash of an off-chain review note, or zero.
    function setStatus(bytes32 reportId, Status status, bytes32 noteHash) external onlyReviewer {
        address author = reportAuthor[reportId];
        if (author == address(0)) revert ReportNotFound(reportId);
        if (author == msg.sender) revert SelfReview();
        _pushStatus(reportId, status, noteHash);
    }

    /// @notice Grant or revoke the reporter role.
    function setReporter(address a, bool allowed) external onlyOwner {
        if (a == address(0)) revert ZeroAddress();
        // forge-lint: disable-next-line(missing-events-access-control) ReporterSet is emitted below
        isReporter[a] = allowed;
        emit ReporterSet(a, allowed);
    }

    /// @notice Grant or revoke the reviewer role.
    function setReviewer(address a, bool allowed) external onlyOwner {
        if (a == address(0)) revert ZeroAddress();
        // forge-lint: disable-next-line(missing-events-access-control) ReviewerSet is emitted below
        isReviewer[a] = allowed;
        emit ReviewerSet(a, allowed);
    }

    /// @notice Start a two-step ownership transfer; `next` must call acceptOwnership. address(0) cancels.
    // forge-lint: disable-next-line(missing-zero-check) address(0) intentionally cancels a pending transfer
    function transferOwnership(address next) external onlyOwner {
        pendingOwner = next;
        emit OwnershipTransferStarted(owner, next);
    }

    /// @notice Complete a pending ownership transfer. Only the pending owner may call.
    function acceptOwnership() external {
        if (msg.sender != pendingOwner || msg.sender == address(0)) revert NotPendingOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    /// @notice Number of revisions of a report (0 if it does not exist).
    function revisionCount(bytes32 reportId) external view returns (uint256) {
        return _revisions[reportId].length;
    }

    /// @notice Revision `index` of a report (0 = original registration).
    function getRevision(bytes32 reportId, uint256 index) external view returns (Revision memory) {
        Revision[] storage revs = _revisions[reportId];
        if (index >= revs.length) revert IndexOutOfRange(index, revs.length);
        return revs[index];
    }

    /// @notice Number of status entries of a report.
    function statusCount(bytes32 reportId) external view returns (uint256) {
        return _statuses[reportId].length;
    }

    /// @notice Status entry `index` of a report, oldest first.
    function getStatusChange(bytes32 reportId, uint256 index) external view returns (StatusChange memory) {
        StatusChange[] storage changes = _statuses[reportId];
        if (index >= changes.length) revert IndexOutOfRange(index, changes.length);
        return changes[index];
    }

    /// @notice Latest status of an existing report; Pending until a reviewer sets one.
    function currentStatus(bytes32 reportId) public view returns (Status) {
        if (reportAuthor[reportId] == address(0)) revert ReportNotFound(reportId);
        StatusChange[] storage changes = _statuses[reportId];
        return changes.length == 0 ? Status.Pending : changes[changes.length - 1].status;
    }

    function _append(bytes32 reportId, bytes32 commitment, uint8 classification) private {
        if (commitment == bytes32(0)) revert ZeroCommitment();
        if (commitmentUsed[commitment]) revert CommitmentAlreadyUsed(commitment);
        if (classification > MAX_CLASSIFICATION) revert InvalidClassification(classification);
        commitmentUsed[commitment] = true;
        _revisions[reportId].push(Revision(commitment, classification, _now(), msg.sender));
    }

    function _pushStatus(bytes32 reportId, Status status, bytes32 noteHash) private {
        _statuses[reportId].push(StatusChange(status, _now(), msg.sender, noteHash));
        emit StatusChanged(reportId, status, msg.sender, noteHash);
    }

    function _now() private view returns (uint64) {
        // casting to 'uint64' is safe because block timestamps stay below 2^64 for ~584 billion years
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(block.timestamp);
    }
}
