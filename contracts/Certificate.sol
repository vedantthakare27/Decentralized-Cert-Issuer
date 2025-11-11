// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Certificate
 * @dev This contract manages the issuance and verification of digital certificates.
 * It stores a fingerprint (hash) of a certificate file, not the file itself.
 */
contract Certificate {

    // --- State Variables ---

    // The address of the institution/person who deployed the contract.
    address public owner;

    // This is the "database" of your blockchain.
    mapping(bytes32 => CertificateData) public certificates;

    // --- Data Structure ---

    // This is a custom data type to store certificate information
    struct CertificateData {
        string studentName;
        string courseName;
        string issueDate;
        bool isIssued;
    }

    // --- Events ---

    // An event that fires when a new certificate is issued
    event CertificateIssued(
        bytes32 indexed certificateHash,
        string studentName,
        string issueDate
    );

    // --- Constructor ---

    // This function runs only ONCE, when the contract is first deployed.
    constructor() {
        owner = msg.sender; // The deployer becomes the owner
    }

    // --- Modifiers ---

    // Ensures only the 'owner' can run the function it modifies
    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can call this function");
        _;
    }

    // --- Functions ---

    /**
     * @dev Issues a new certificate. Only the owner can call this.
     * @param _hash The IPFS hash (fingerprint) of the certificate file.
     */
    function issueCertificate(
        bytes32 _hash,
        string memory _studentName,
        string memory _courseName,
        string memory _issueDate
    ) public onlyOwner {
        
        require(certificates[_hash].isIssued == false, "Certificate already exists");

        // Store the new certificate data
        certificates[_hash] = CertificateData(
            _studentName,
            _courseName,
            _issueDate,
            true
        );

        // Fire the event to log this action
        emit CertificateIssued(_hash, _studentName, _issueDate);
    }

    /**
     * @dev Verifies a certificate. Anyone can call this function for free.
     * @param _hash The IPFS hash (fingerprint) to check.
     */
    function verifyCertificate(bytes32 _hash)
        public
        view
        returns (
            bool isIssued,
            string memory studentName,
            string memory courseName,
            string memory issueDate
        )
    {
        CertificateData storage cert = certificates[_hash];
        
        return (
            cert.isIssued,
            cert.studentName,
            cert.courseName,
            cert.issueDate
        );
    }
}