//SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.22;

contract DocumentStorage {
    struct Document {
        uint256 id;
        string clientName;
        string fileHash;
    }

    mapping(uint256 => Document) private documents;
    uint256 private documentCount;

    event DocumentUploaded(uint256 indexed id, string clientName,string fileHash);

    function uploadDocument(string memory clientName, string memory fileHash) public {
        documentCount++;
        documents[documentCount] = Document(documentCount,  clientName, fileHash);
        emit DocumentUploaded(documentCount, clientName, fileHash);
        
    }

    function getDocumentHash(uint256 _id) public view returns (string memory) {
        //require(_id > 0 && _id <= documentCount, "Invalid document ID");
        if (_id > 0 && _id <= documentCount){
            return documents[_id].fileHash;
        }else{
            return "Document ID not Found in Blockchain";
        }
        
    }

    function getDocumentOwner(uint256 _id) public view returns (string memory) {
        //require(_id > 0 && _id <= documentCount, "Invalid document ID");
        if (_id > 0 && _id <= documentCount){
            return documents[_id].clientName;
        }else{
            return "Document ID not Found in Blockchain";
        }
        
    }
}
