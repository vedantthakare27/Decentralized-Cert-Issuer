import React, { useState, useEffect, useCallback } from 'react';
import { BrowserProvider, Contract, ethers } from 'ethers';
import axios from 'axios';
import './App.css'; 

const contractABI = require('./utils/Certificate.json').abi;
const contractAddress = process.env.REACT_APP_CONTRACT_ADDRESS ? process.env.REACT_APP_CONTRACT_ADDRESS.trim() : null;
const pinataJwt = process.env.REACT_APP_PINATA_JWT;

function App() {
  const [currentAccount, setCurrentAccount] = useState(null);
  const [signer, setSigner] = useState(null); 
  const [certificateContract, setCertificateContract] = useState(null);
  
  const [studentName, setStudentName] = useState('');
  const [courseName, setCourseName] = useState('');
  const [issueDate, setIssueDate] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [issuingStatus, setIssuingStatus] = useState('');
  
  const [verifyHash, setVerifyHash] = useState('');
  const [verificationResult, setVerificationResult] = useState(null);

  const initializeContract = (newSigner) => {
    if (contractAddress && contractABI) {
      try {
        // FIX: Ensure '0x' prefix is present but skip strict checksum validation
        const prefixedAddress = contractAddress.startsWith('0x') 
          ? contractAddress 
          : `0x${contractAddress}`;
        
        // Use the prefixed address directly
        const validatedAddress = prefixedAddress; 
        
        const contract = new Contract(validatedAddress, contractABI, newSigner);
        setCertificateContract(contract);
        console.log('Contract Initialized:', validatedAddress);
      } catch (error) {
        console.error("Contract Initialization Error:", error);
        setIssuingStatus('Contract Initialization Failed: Check Contract Address in .env');
      }
    }
  };

  const checkIfWalletIsConnected = useCallback(async () => {
    try {
      const { ethereum } = window;
      if (!ethereum) return alert("Make sure you have MetaMask installed!");
      
      const accounts = await ethereum.request({ method: "eth_accounts" });

      if (accounts.length !== 0) {
        const account = accounts[0];
        setCurrentAccount(account);
        
        const provider = new BrowserProvider(ethereum);
        const newSigner = await provider.getSigner();
        setSigner(newSigner);
        initializeContract(newSigner);
      } 
    } catch (error) {
      console.log(error);
    }
  }, [contractAddress, contractABI]);

  const connectWallet = async () => {
    try {
      const { ethereum } = window;
      if (!ethereum) return alert("Get MetaMask!");

      const accounts = await ethereum.request({ method: "eth_requestAccounts" });
      setCurrentAccount(accounts[0]);
      
      const provider = new BrowserProvider(ethereum);
      const newSigner = await provider.getSigner();
      setSigner(newSigner);
      initializeContract(newSigner);

    } catch (error) {
      console.log(error);
    }
  };

  useEffect(() => {
    checkIfWalletIsConnected();
  }, [checkIfWalletIsConnected]); 

  const uploadFileToPinata = async (file) => {
    setIssuingStatus('Uploading file to IPFS...');
    if (!pinataJwt) {
      throw new Error("PINATA_JWT is not set in .env file.");
    }

    const formData = new FormData();
    formData.append('file', file);

    const url = 'https://api.pinata.cloud/pinning/pinFileToIPFS';
    
    try {
        const response = await axios.post(url, formData, {
            maxBodyLength: Infinity,
            headers: {
                'Content-Type': `multipart/form-data; boundary=${formData._boundary}`,
                'Authorization': `Bearer ${pinataJwt}`
            }
        });

        return response.data.IpfsHash; 
    } catch (error) {
        console.error("Pinata Upload Error:", error);
        setIssuingStatus(`IPFS Upload Failed: ${error.message}`);
        throw new Error("IPFS upload failed.");
    }
  };

  const issueCertificate = async (e) => {
    e.preventDefault();
    if (!certificateContract || !selectedFile || !studentName || !courseName || !issueDate) {
      setIssuingStatus('Please fill all fields and select a file.');
      return;
    }
    
    try {
      const ipfsHash = await uploadFileToPinata(selectedFile);
      setIssuingStatus(`File uploaded. IPFS Hash (CID): ${ipfsHash}`);

      const hashBytes32 = ethers.keccak256(ethers.toUtf8Bytes(ipfsHash));
      setIssuingStatus(`Registering hash on blockchain: ${hashBytes32.substring(0, 8)}...`);

      const tx = await certificateContract.issueCertificate(
        hashBytes32,
        studentName,
        courseName,
        issueDate
      );

      setIssuingStatus(`Transaction submitted: ${tx.hash.substring(0, 10)}... Waiting for confirmation.`);
      await tx.wait(); 
      setIssuingStatus(`✅ Success! Certificate Issued & Recorded! IPFS Link: https://gateway.pinata.cloud/ipfs/${ipfsHash}`);

    } catch (error) {
      console.error("Issuing Error:", error);
      setIssuingStatus(`Issuing Failed: ${error.message || error.code || 'Check MetaMask for details'}`);
    }
  };
  
  const verifyCertificate = async (e) => {
    e.preventDefault();
    setVerificationResult(null);
    if (!certificateContract || !verifyHash) {
      setVerificationResult({ error: 'Please enter a certificate hash (CID or bytes32).' });
      return;
    }

    try {
        let hashBytes32;

        if (verifyHash.startsWith('0x') && verifyHash.length === 66) {
            hashBytes32 = verifyHash;
        } else if (verifyHash.length >= 46 && verifyHash.length <= 59 && !verifyHash.startsWith('0x')) {
            hashBytes32 = ethers.keccak256(ethers.toUtf8Bytes(verifyHash));
        } else {
            setVerificationResult({ error: 'Invalid hash format. Please enter a valid CID or bytes32 hash.' });
            return;
        }
        
        setVerificationResult({ status: `Checking hash: ${hashBytes32.substring(0, 8)}...` });

        const result = await certificateContract.verifyCertificate(hashBytes32);
        
        const isIssued = result[0];
        
        if (isIssued) {
          setVerificationResult({
            success: true,
            isIssued: true,
            studentName: result[1],
            courseName: result[2],
            issueDate: result[3],
            ipfsHash: verifyHash.startsWith('0x') ? 'Hash is bytes32' : verifyHash
          });
        } else {
          setVerificationResult({ isIssued: false });
        }
    } catch (error) {
      console.error("Verification Error:", error);
      setVerificationResult({ error: error.message || 'An unknown error occurred during verification.' });
    }
  };


  const renderConnectWalletButton = () => (
    <button className="connect-button" onClick={connectWallet}>
      Connect Wallet
    </button>
  );
  
  const renderIssuerPanel = () => (
    <div className="panel issuer-panel">
      <h2>Issuance Panel (Owner Only)</h2>
      <form onSubmit={issueCertificate}>
        <input 
          type="text" 
          placeholder="Student Name" 
          value={studentName} 
          onChange={(e) => setStudentName(e.target.value)} 
          required 
        />
        <input 
          type="text" 
          placeholder="Course Name" 
          value={courseName} 
          onChange={(e) => setCourseName(e.target.value)} 
          required 
        />
        <input 
          type="date" 
          placeholder="Issue Date" 
          value={issueDate} 
          onChange={(e) => setIssueDate(e.target.value)} 
          required 
        />
        <input 
          type="file" 
          onChange={(e) => setSelectedFile(e.target.files[0])} 
          required 
        />
        <button type="submit" disabled={!certificateContract || !signer}>
          Issue Certificate & Record Hash
        </button>
      </form>
      {issuingStatus && <p className="status">{issuingStatus}</p>}
    </div>
  );
  
  const renderVerifierPanel = () => (
    <div className="panel verifier-panel">
      <h2>Certificate Verification</h2>
      <p>Enter the IPFS Hash (CID) or the bytes32 Hash:</p>
      <form onSubmit={verifyCertificate}>
        <input 
          type="text" 
          placeholder="IPFS Hash (CID) or Bytes32 Hash" 
          value={verifyHash} 
          onChange={(e) => setVerifyHash(e.target.value)} 
          required 
        />
        <button type="submit" disabled={!certificateContract}>
          Verify on Blockchain
        </button>
      </form>
      
      {verificationResult && (
        <div className="verification-output">
          {verificationResult.status && <p className="status">{verificationResult.status}</p>}
          {verificationResult.error && <p className="error">Verification Error: {verificationResult.error}</p>}
          
          {verificationResult.isIssued === true && (
            <div className="success">
              <h3>✅ Verification Successful!</h3>
              <p>The certificate hash is **valid and recorded**.</p>
              <p>Name: **{verificationResult.studentName}**</p>
              <p>Course: **{verificationResult.courseName}**</p>
              <p>Date: **{verificationResult.issueDate}**</p>
              {verificationResult.ipfsHash !== 'Hash is bytes32' && (
                  <p>View File: <a href={`https://gateway.pinata.cloud/ipfs/${verificationResult.ipfsHash}`} target="_blank" rel="noopener noreferrer">Download Certificate (IPFS Link)</a></p>
              )}
            </div>
          )}
          
          {verificationResult.isIssued === false && (
            <p className="failure">❌ Verification Failed: This certificate hash is **NOT** recorded on the blockchain.</p>
          )}
        </div>
      )}
    </div>
  );


  return (
    <div className="App">
      <header className="App-header">
        <h1>🎓 Decentralized Certificate Issuer</h1>
        <p>Connected Account: {currentAccount ? currentAccount : 'Not Connected'}</p>
        <p>Contract: {contractAddress ? `${contractAddress.substring(0, 6)}...` : 'Loading Address'}</p>
        
        {currentAccount ? (
          <div className="main-content">
            {renderIssuerPanel()}
            {renderVerifierPanel()}
          </div>
        ) : (
          renderConnectWalletButton()
        )}
      </header>
    </div>
  );
}

export default App;