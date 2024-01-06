//SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.22;

contract UserAccount {
    struct User {
        string name;
        string email;
        string companyName;
        AccountType accountType;
    }

    enum AccountType {Verifier, Requester}

    mapping(address => User) private users;
    address private documentStorageContractAddress;

    event UserRegistered(address indexed userAddress, string name, string email, string companyName, AccountType accountType);

    modifier onlyVerifier() {
        require(users[msg.sender].accountType == AccountType.Verifier, "Only verifiers can perform this action");
        _;
    }

    constructor(address _documentStorageContractAddress) {
        documentStorageContractAddress = _documentStorageContractAddress;
    }

    function registerUser(
        string memory _name,
        string memory _email,
        string memory _companyName,
        AccountType _accountType
    ) public {
        require(bytes(_name).length > 0, "Name cannot be empty");
        require(bytes(_email).length > 0, "Email cannot be empty");
        require(bytes(_companyName).length > 0, "Company name cannot be empty");
        require(_accountType == AccountType.Verifier || _accountType == AccountType.Requester, "Invalid account type");

        users[msg.sender] = User(_name, _email, _companyName, _accountType);
        emit UserRegistered(msg.sender, _name, _email, _companyName, _accountType);
    }

    function getUserDetails(address _userAddress) public view returns (string memory, string memory, string memory, AccountType) {
        User storage user = users[_userAddress];
        return (user.name, user.email, user.companyName, user.accountType);
    }

    function uploadDocument(string memory clientName, string memory _fileHash) public {
       
       IDocumentStorage(documentStorageContractAddress).uploadDocument(clientName, _fileHash);
       

    }

    function getDocumentHash(uint256 _id) public view returns (string memory) {
        return IDocumentStorage(documentStorageContractAddress).getDocumentHash(_id);
    }

    function getDocumentOwner(uint256 _id) public view returns (string memory) {
        return IDocumentStorage(documentStorageContractAddress).getDocumentOwner(_id);
    }
}

interface IDocumentStorage {
    function uploadDocument(string memory clientName, string memory _fileHash) external;
    function getDocumentHash(uint256 _id) external view returns (string memory);
    function getDocumentOwner(uint256 _id) external view returns (string memory);
}