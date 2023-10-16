// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Context.sol";

contract StateIdentification is Context, Pausable, Ownable {
    using ECDSA for bytes32;

    address public admin;
    IERC20 public pointToken;
    mapping(address => uint256) public balances;
    mapping(bytes32 => bool) public usedNonces;
    mapping(uint256 => mapping(address => bool)) public votes; 
    mapping(uint256 => uint256) public voteWeights;  
    mapping(uint256 => uint256) public totalWeights;  
    uint256 public nextVoteId;
    uint256 public reserveBalance;

    event VoteStarted(uint256 voteId, address indexed participant);
    event Voted(uint256 voteId, address indexed voter, uint256 weight);
    event AdminChanged(address indexed newAdmin);
    event ChannelOpened(address indexed participant, uint256 amount);
    event ChannelStateUpdated(address indexed participant, uint256 newBalance);
    event ChannelClosed(address indexed participant, uint256 amount);
    event ChannelClosedByDAO(address indexed participant, uint256 amount, uint256 voteId);
    event DepositedToReserve(uint256 amount);
    event WithdrawnFromReserve(uint256 amount);

    constructor(address admin_, IERC20 pointToken_, uint256 initialReserveBalance, address initialOwner) Ownable(initialOwner) {
        admin = admin_;
        pointToken = pointToken_;
        nextVoteId = 1;
        reserveBalance = initialReserveBalance;
    }

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function depositToReserve(uint256 amount) external onlyAdmin whenNotPaused {
        require(pointToken.transferFrom(_msgSender(), address(this), amount), "Transfer failed");
        reserveBalance += amount;
        emit DepositedToReserve(amount);
    }

    function withdrawFromReserve(uint256 amount) external onlyAdmin whenNotPaused {
        require(reserveBalance >= amount, "Insufficient reserve balance");
        require(pointToken.transfer(_msgSender(), amount), "Transfer failed");
        reserveBalance -= amount;
        emit WithdrawnFromReserve(amount);
    }
 
    modifier onlyAdmin() {
        require(_msgSender() == admin, "Only admin can perform this action");
        _;
    }

    function changeAdmin(address newAdmin) external onlyOwner whenNotPaused {
        require(newAdmin != address(0), "New admin address cannot be zero address");
        admin = newAdmin;
        emit AdminChanged(newAdmin);
    }

    function openChannel(uint256 amount) external whenNotPaused {
        require(pointToken.transferFrom(_msgSender(), address(this), amount), "Transfer failed");
        balances[_msgSender()] += amount;
        emit ChannelOpened(_msgSender(), amount);
    }

    function _updateBalance(address participant, uint256 newBalance) internal {
        if (balances[participant] < newBalance) {
            uint256 shortfall = newBalance - balances[participant];
            require(reserveBalance >= shortfall, "Not enough reserve balance");
            reserveBalance -= shortfall;
            balances[participant] += shortfall;
        } else if (balances[participant] > newBalance) {
            uint256 excess = balances[participant] - newBalance;
            reserveBalance += excess;
            balances[participant] -= excess;
        }
    }

    function _verifyBatchSignature(address[] calldata participants, uint256[] calldata newBalances, uint256 nonce, bytes calldata adminSignature) internal {
        bytes32 hash = keccak256(abi.encodePacked(participants, newBalances, nonce));
        require(admin == hash.recover(adminSignature), "Invalid signature");
        require(!usedNonces[hash], "Nonce already used");
        usedNonces[hash] = true;
    }

    function _verifySignature(address participant, uint256 newBalance, uint256 nonce, bytes calldata adminSignature) internal {
        bytes32 hash = keccak256(abi.encodePacked(participant, newBalance, nonce));
        require(admin == hash.recover(adminSignature), "Invalid signature");
        require(!usedNonces[hash], "Nonce already used");
        usedNonces[hash] = true;
    }

    function updateChannelState(uint256 newBalance, uint256 channel_nonce, bytes calldata adminSignature) external whenNotPaused {
        _verifySignature(_msgSender(), newBalance, channel_nonce, adminSignature);

        _updateBalance(_msgSender(), newBalance);

        emit ChannelStateUpdated(_msgSender(), newBalance);
    }
      
    function closeChannel(uint256 newBalance, uint256 close_nonce, bytes calldata adminSignature) external whenNotPaused {
        _verifySignature(_msgSender(), newBalance, close_nonce, adminSignature);

        _updateBalance(_msgSender(), newBalance);

        require(pointToken.transfer(_msgSender(), newBalance), "Transfer failed");

        balances[_msgSender()] = 0;

        emit ChannelClosed(_msgSender(), newBalance);
    }

    function vote(uint256 voteId, bool approve) external whenNotPaused {
        require(balances[_msgSender()] > 0, "No balance to vote");
        require(!votes[voteId][_msgSender()], "Already voted");

        votes[voteId][_msgSender()] = true;
        uint256 weight = balances[_msgSender()];
        if (approve) {
            voteWeights[voteId] += weight;
        }

        emit Voted(voteId, _msgSender(), weight);
    }

    function startVoteToCloseChannel(address participant) external onlyOwner whenNotPaused {
        require(balances[participant] > 0, "No balance to dispute");

        uint256 voteId = nextVoteId++;
        totalWeights[voteId] = pointToken.balanceOf(address(this));
        emit VoteStarted(voteId, participant);
    }

    function closeChannelByDAO(address participant, uint256 newBalance, uint256 voteId) external whenNotPaused {
        require(voteWeights[voteId] * 2 >= totalWeights[voteId], "Not enough votes to close channel");

        _updateBalance(participant, newBalance);

        require(pointToken.transfer(participant, newBalance), "Transfer failed");

        balances[participant] = 0;

        emit ChannelClosedByDAO(participant, newBalance, voteId);
    }

}
