// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title VulnerableGovernance
 * @notice DELIBERATELY VULNERABLE - DO NOT USE IN PRODUCTION
 * @dev Contains vulnerabilities:
 * 1. Vote manipulation through flash loans
 * 2. Missing timelock on execution
 * 3. Delegate frontrunning
 * 4. No vote weight snapshots
 * 5. Proposal execution without quorum checks
 */
contract VulnerableGovernance {
    IERC20 public governanceToken;

    struct Proposal {
        address proposer;
        address target;
        bytes data;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 startBlock;
        uint256 endBlock;
        bool executed;
        bool canceled;
        mapping(address => bool) hasVoted;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;

    uint256 public votingPeriod = 100 days;
    uint256 public proposalThreshold = 1000e18; // 1000 tokens to propose

    // VULNERABILITY: No quorum requirement
    uint256 public quorum = 0;

    event ProposalCreated(uint256 indexed proposalId, address proposer, address target);
    event VoteCast(address indexed voter, uint256 indexed proposalId, bool support, uint256 votes);
    event ProposalExecuted(uint256 indexed proposalId);

    constructor(address _governanceToken) {
        governanceToken = IERC20(_governanceToken);
    }

    /**
     * @notice VULNERABILITY 1: Flash loan attack - no snapshot
     * @dev Uses current balance instead of snapshot at proposal creation
     */
    function propose(address target, bytes memory data) external returns (uint256) {
        // VULNERABILITY: Check happens at proposal time, but votes use current balance
        require(
            governanceToken.balanceOf(msg.sender) >= proposalThreshold,
            "Below threshold"
        );

        uint256 proposalId = proposalCount++;
        Proposal storage proposal = proposals[proposalId];

        proposal.proposer = msg.sender;
        proposal.target = target;
        proposal.data = data;
        proposal.startBlock = block.number;
        proposal.endBlock = block.number + votingPeriod;

        emit ProposalCreated(proposalId, msg.sender, target);
        return proposalId;
    }

    /**
     * @notice VULNERABILITY 1: Vote weight based on current balance
     * @dev Allows flash loan attacks to manipulate votes
     */
    function castVote(uint256 proposalId, bool support) external {
        Proposal storage proposal = proposals[proposalId];

        require(block.number >= proposal.startBlock, "Voting not started");
        require(block.number <= proposal.endBlock, "Voting ended");
        require(!proposal.hasVoted[msg.sender], "Already voted");

        // VULNERABILITY: Uses current balance, not snapshot!
        uint256 votes = governanceToken.balanceOf(msg.sender);
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
     * @notice VULNERABILITY 2: No timelock before execution
     * @notice VULNERABILITY 5: No quorum check
     * @dev Can be executed immediately after voting period
     */
    function execute(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        require(block.number > proposal.endBlock, "Voting not ended");
        require(!proposal.executed, "Already executed");
        require(!proposal.canceled, "Proposal canceled");

        // VULNERABILITY: No timelock delay
        // VULNERABILITY: No quorum check - even 1 vote can pass
        require(proposal.forVotes > proposal.againstVotes, "Proposal failed");

        proposal.executed = true;

        // VULNERABILITY: No check on call success beyond require
        (bool success, ) = proposal.target.call(proposal.data);
        require(success, "Execution failed");

        emit ProposalExecuted(proposalId);
    }

    /**
     * @notice VULNERABILITY 4: Anyone can cancel any proposal
     */
    function cancel(uint256 proposalId) external {
        Proposal storage proposal = proposals[proposalId];

        // VULNERABILITY: No access control - anyone can cancel!
        require(!proposal.executed, "Already executed");
        require(!proposal.canceled, "Already canceled");

        proposal.canceled = true;
    }

    /**
     * @notice VULNERABILITY 3: Delegate can be frontrun
     * @dev Simple delegation without protection
     */
    mapping(address => address) public delegates;

    function delegate(address delegatee) external {
        // VULNERABILITY: Can be frontrun to steal delegation
        delegates[msg.sender] = delegatee;
    }

    function getVotes(address account) public view returns (uint256) {
        // VULNERABILITY: Doesn't account for delegated votes properly
        return governanceToken.balanceOf(account);
    }

    /**
     * @notice VULNERABILITY: No access control
     */
    function setVotingPeriod(uint256 newPeriod) external {
        // VULNERABILITY: Anyone can change voting period!
        votingPeriod = newPeriod;
    }

    /**
     * @notice VULNERABILITY: No access control
     */
    function setQuorum(uint256 newQuorum) external {
        // VULNERABILITY: Anyone can set quorum, even to 0!
        quorum = newQuorum;
    }
}
