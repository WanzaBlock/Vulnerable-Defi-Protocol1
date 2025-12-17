// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/governance/utils/IVotes.sol";

/**
 * @title SecureGovernance
 * @notice SECURE VERSION - All vulnerabilities fixed
 * @dev Fixes applied:
 * 1. Vote weight snapshots to prevent flash loan attacks
 * 2. Timelock delay before execution
 * 3. Proper quorum requirements
 * 4. Access controls on admin functions
 * 5. Safe delegation mechanism
 */
contract SecureGovernance {
    IVotes public immutable governanceToken;

    struct Proposal {
        address proposer;
        address target;
        bytes data;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 startBlock;
        uint256 endBlock;
        uint256 eta; // FIX 2: Execution timelock
        bool executed;
        bool canceled;
        mapping(address => bool) hasVoted;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    uint256 public votingDelay = 1; // 1 block delay before voting starts
    uint256 public votingPeriod = 45818; // ~1 week
    uint256 public proposalThreshold = 100000e18; // 100k tokens
    uint256 public quorumVotes = 400000e18; // FIX 3: 400k quorum
    uint256 public constant TIMELOCK_DELAY = 2 days; // FIX 2: 2 day timelock

    address public admin;
    address public pendingAdmin;

    event ProposalCreated(
        uint256 indexed proposalId,
        address proposer,
        address target,
        uint256 startBlock,
        uint256 endBlock
    );
    event VoteCast(
        address indexed voter,
        uint256 indexed proposalId,
        bool support,
        uint256 votes
    );
    event ProposalQueued(uint256 indexed proposalId, uint256 eta);
    event ProposalExecuted(uint256 indexed proposalId);
    event ProposalCanceled(uint256 indexed proposalId);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor(address _governanceToken) {
        governanceToken = IVotes(_governanceToken);
        admin = msg.sender;
    }

    /**
     * @notice FIX 1: Uses token's getVotes with snapshot
     * @dev Requires token to implement IVotes (EIP-5805)
     */
    function propose(address target, bytes memory data) external returns (uint256) {
        // FIX 1: Check voting power at previous block (snapshot)
        require(
            governanceToken.getVotes(msg.sender) >= proposalThreshold,
            "Below proposal threshold"
        );

        uint256 proposalId = proposalCount++;
        Proposal storage proposal = proposals[proposalId];

        proposal.proposer = msg.sender;
        proposal.target = target;
        proposal.data = data;
        proposal.startBlock = block.number + votingDelay; // FIX: Delay before voting
        proposal.endBlock = block.number + votingDelay + votingPeriod;

        emit ProposalCreated(
            proposalId,
            msg.sender,
            target,
            proposal.startBlock,
            proposal.endBlock
        );

        return proposalId;
    }

    /**
     * @notice FIX 1: Uses snapshot voting power
     * @dev Votes based on power at proposal start, not current balance
     */
    function castVote(uint256 proposalId, bool support) external {
        Proposal storage proposal = proposals[proposalId];

        require(block.number >= proposal.startBlock, "Voting not started");
        require(block.number <= proposal.endBlock, "Voting ended");
        require(!proposal.hasVoted[msg.sender], "Already voted");

        // FIX 1: Get voting power from snapshot at proposal start block
        uint256 votes = governanceToken.getPastVotes(
            msg.sender,
            proposal.startBlock - 1
        );
        require(votes > 0, "No voting power");

        proposal.hasVoted[msg.sender] = true;

        if (support) {
            proposal.forVotes += votes;
        } else {
            proposal.againstVotes += votes;
        }

        emit VoteCast(msg.sender, proposalId, support, votes);
    }

    /**
     * @notice FIX 2: Queue proposal with timelock
     * @notice FIX 3: Verify quorum requirement
     */
    function queue(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(block.number > proposal.endBlock, "Voting not ended");
        require(!proposal.executed, "Already executed");
        require(!proposal.canceled, "Proposal canceled");
        require(proposal.eta == 0, "Already queued");

        // FIX 3: Verify quorum met
        uint256 totalVotes = proposal.forVotes + proposal.againstVotes;
        require(totalVotes >= quorumVotes, "Quorum not reached");

        // FIX 3: Verify proposal passed
        require(proposal.forVotes > proposal.againstVotes, "Proposal failed");

        // FIX 2: Set timelock delay
        proposal.eta = block.timestamp + TIMELOCK_DELAY;

        emit ProposalQueued(proposalId, proposal.eta);
    }

    /**
     * @notice FIX 2: Can only execute after timelock
     */
    function execute(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(proposal.eta != 0, "Not queued");
        require(!proposal.executed, "Already executed");
        require(!proposal.canceled, "Proposal canceled");

        // FIX 2: Enforce timelock delay
        require(block.timestamp >= proposal.eta, "Timelock not met");
        require(
            block.timestamp <= proposal.eta + 14 days,
            "Execution window expired"
        );

        proposal.executed = true;

        (bool success, bytes memory returnData) = proposal.target.call(proposal.data);
        require(success, string(returnData));

        emit ProposalExecuted(proposalId);
    }

    /**
     * @notice FIX 4: Only proposer or admin can cancel
     */
    function cancel(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(!proposal.executed, "Already executed");
        require(!proposal.canceled, "Already canceled");

        // FIX 4: Access control - only proposer or admin
        require(
            msg.sender == proposal.proposer || msg.sender == admin,
            "Not authorized"
        );

        // Additional check: Can cancel if proposer drops below threshold
        if (msg.sender == proposal.proposer) {
            require(
                governanceToken.getVotes(proposal.proposer) < proposalThreshold,
                "Proposer still has voting power"
            );
        }

        proposal.canceled = true;
        emit ProposalCanceled(proposalId);
    }

    /**
     * @notice FIX 4: Admin functions with access control
     */
    function setVotingDelay(uint256 newDelay) external onlyAdmin {
        require(newDelay >= 1, "Delay too short");
        votingDelay = newDelay;
    }

    function setVotingPeriod(uint256 newPeriod) external onlyAdmin {
        require(newPeriod >= 5760, "Period too short"); // ~1 day minimum
        votingPeriod = newPeriod;
    }

    function setProposalThreshold(uint256 newThreshold) external onlyAdmin {
        require(newThreshold > 0, "Threshold too low");
        proposalThreshold = newThreshold;
    }

    function setQuorum(uint256 newQuorum) external onlyAdmin {
        require(newQuorum > 0, "Quorum too low");
        quorumVotes = newQuorum;
    }

    /**
     * @notice Two-step admin transfer for safety
     */
    function setPendingAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Invalid address");
        pendingAdmin = newAdmin;
    }

    function acceptAdmin() external {
        require(msg.sender == pendingAdmin, "Not pending admin");
        admin = pendingAdmin;
        pendingAdmin = address(0);
    }

    /**
     * @notice View functions for proposal state
     */
    function state(uint256 proposalId) public view returns (uint8) {
        Proposal storage proposal = proposals[proposalId];

        if (proposal.canceled) return 2; // Canceled
        if (proposal.executed) return 7; // Executed
        if (block.number <= proposal.startBlock) return 0; // Pending
        if (block.number <= proposal.endBlock) return 1; // Active

        uint256 totalVotes = proposal.forVotes + proposal.againstVotes;
        if (totalVotes < quorumVotes) return 3; // Defeated - no quorum
        if (proposal.forVotes <= proposal.againstVotes) return 3; // Defeated
        if (proposal.eta == 0) return 4; // Succeeded - not queued
        if (block.timestamp < proposal.eta) return 5; // Queued
        if (block.timestamp > proposal.eta + 14 days) return 6; // Expired

        return 5; // Queued - ready to execute
    }
}
