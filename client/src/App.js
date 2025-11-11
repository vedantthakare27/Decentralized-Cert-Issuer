import React, { useState, useEffect, useCallback } from 'react';
import { BrowserProvider, Contract, ethers } from 'ethers'; 
import axios from 'axios';
import './App.css'; 

// Load ABI and Environment Variables
const contractABI = require('./utils/Certificate.json').abi;
const contractAddress = process.env.REACT_APP_CONTRACT_ADDRESS ? process.env.REACT_APP_CONTRACT_ADDRESS.trim() : null;
const pinataJwt = process.env.REACT_APP_PINATA_JWT;

// Define Sepolia Chain ID globally and a known public RPC for stability
const SEPOLIA_CHAIN_ID = 11155111; 
// Using a standard public RPC URL for Sepolia to stabilize network context for Ethers v6
const SEPOLIA_RPC_URL = 'https://rpc.sepolia.org'; 

function App() {
  // State variables
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

  // Function to initialize the contract object
  const initializeContract = (newSigner) => {
    if (contractAddress && contractABI) {
      try {
        // Ensure '0x' prefix is present
        const prefixedAddress = contractAddress.startsWith('0x') 
          ? contractAddress 
          : `0x${contractAddress}`;
        
        const validatedAddress = prefixedAddress; 
        
        const contract = new Contract(validatedAddress, contractABI, newSigner);
        setCertificateContract(contract);
        console.log('Contract Initialized:', validatedAddress);
        setIssuingStatus('');
      } catch (error) {
        console.error("Contract Initialization Error:", error);
        setIssuingStatus('Contract Initialization Failed: Check Contract Address in .env');
      }
    }
  };

  // Function to set up the wallet connection and check network
  const setupWalletAndSigner = useCallback(async (ethereum, accounts) => {
    try {
        // 1. Check current network Chain ID from the wallet (Rabby)
        const chainIdHex = await ethereum.request({ method: 'eth_chainId' });
        const currentChainId = parseInt(chainIdHex, 16);

        if (currentChainId !== SEPOLIA_CHAIN_ID) {
            setIssuingStatus('Please switch Rabby Wallet to the Sepolia Test Network (Chain ID: 11155111).');
            return false;
        }

        // 2. Create the provider explicitly passing the SEPOLIA_RPC_URL for network stability
        const provider = new BrowserProvider(ethereum, SEPOLIA_RPC_URL);
        
        // 3. Get the Signer (Crucial for sending transactions)
        const newSigner = await provider.getSigner();

        setCurrentAccount(accounts[0]);
        setSigner(newSigner);
        initializeContract(newSigner);
        return true;
    } catch (error) {
        console.error("Setup Wallet Error:", error);
        setIssuingStatus(`Setup Failed: ${error.message || 'Check Rabby Wallet configuration.'}`);
        return false;
    }
  }, [contractAddress, contractABI]);


  const checkIfWalletIsConnected = useCallback(async () => {
    try {
      const { ethereum } = window;
      if (!ethereum) return;
      
      const accounts = await ethereum.request({ method: "eth_accounts" });

      if (accounts.length !== 0) {
        await setupWalletAndSigner(ethereum, accounts);
      } 
    } catch (error) {
      console.log(error);
    }
  }, [setupWalletAndSigner]);

  const connectWallet = async () => {
    try {
      const { ethereum } = window;
      if (!ethereum) return console.log("Please install a wallet extension like Rabby or MetaMask.");

      // Request accounts and trigger connection
      const accounts = await ethereum.request({ method: "eth_requestAccounts" });
      await setupWalletAndSigner(ethereum, accounts);

    } catch (error) {
      console.log(error);
      setIssuingStatus(`Connection Error: ${error.message || 'Check your wallet for connection request.'}`);
    }
  };

  useEffect(() => {
    checkIfWalletIsConnected();
    // Set up listener for account or network changes
    if (window.ethereum) {
        // Reload the page if the network or account changes to re-initialize everything
        const handleChainChanged = () => window.location.reload();
        window.ethereum.on('chainChanged', handleChainChanged);
        window.ethereum.on('accountsChanged', handleChainChanged);
        return () => {
            window.ethereum.removeListener('chainChanged', handleChainChanged);
            window.ethereum.removeListener('accountsChanged', handleChainChanged);
        };
    }
  }, [checkIfWalletIsConnected]); 

  // IPFS Upload Logic
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

  // Certificate Issuance (Write function)
  const issueCertificate = async (e) => {
    e.preventDefault();
    if (!certificateContract || !selectedFile || !studentName || !courseName || !issueDate) {
      setIssuingStatus('Please fill all fields and select a file.');
      return;
    }
    
    if (!signer) {
        setIssuingStatus('Wallet is connected, but signer is missing. Please ensure Rabby is fully initialized and on Sepolia.');
        return;
    }

    try {
      // FINAL DEFENSIVE CHECK: Force network check one more time before transaction
      const currentChainIdHex = await window.ethereum.request({ method: 'eth_chainId' });
      const currentChainId = parseInt(currentChainIdHex, 16);
      if (currentChainId !== SEPOLIA_CHAIN_ID) {
          throw new Error('Wallet is on incorrect network. Please switch to Sepolia (11155111).');
      }

      const ipfsHash = await uploadFileToPinata(selectedFile);
      setIssuingStatus(`File uploaded. IPFS Hash (CID): ${ipfsHash}`);

      const hashBytes32 = ethers.keccak256(ethers.toUtf8Bytes(ipfsHash));
      setIssuingStatus(`Registering hash on blockchain: ${hashBytes32.substring(0, 8)}...`);

      // Connect the contract to the signer to send a transaction
      const contractWithSigner = certificateContract.connect(signer);
      
      const tx = await contractWithSigner.issueCertificate(
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
      // Catch specific errors related to network context
      if (error.code === 'UNCONFIGURED_NAME' || error.message.includes('network is not supported') || error.message.includes('chain is not currently supported') || error.message.includes('Wallet is on incorrect network')) {
         setIssuingStatus(`Issuing Failed: Network Error. Please ensure Rabby is on Sepolia (Chain ID: 11155111) and refresh.`);
      } else {
         setIssuingStatus(`Issuing Failed: ${error.message || error.code || 'Check Rabby for transaction details.'}`);
      }
    }
  };
  
  // Certificate Verification (Read function)
  const verifyCertificate = async (e) => {
    e.preventDefault();
    setVerificationResult(null);
    if (!certificateContract || !verifyHash) {
      setVerificationResult({ error: 'Please enter a certificate hash (CID or bytes32).' });
      return;
    }

    try {
        let hashBytes32;

        // Determine if input is CID or bytes32 hash and calculate bytes32 if necessary
        if (verifyHash.startsWith('0x') && verifyHash.length === 66) {
            hashBytes32 = verifyHash;
        } else if (verifyHash.length >= 46 && verifyHash.length <= 59 && !verifyHash.startsWith('0x')) {
            hashBytes32 = ethers.keccak256(ethers.toUtf8Bytes(verifyHash));
        } else {
            setVerificationResult({ error: 'Invalid hash format. Please enter a valid CID or bytes32 hash.' });
            return;
        }
        
        setVerificationResult({ status: `Checking hash: ${hashBytes32.substring(0, 8)}...` });

        // Call the read-only function
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

  // --- UI Rendering Functions (Minimum Styling) ---

  const renderConnectWalletButton = () => (
    <button className="connect-button w-full bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 transition duration-300" onClick={connectWallet}>
      Connect Wallet
    </button>
  );
  
  const renderIssuerPanel = () => (
    <div className="panel issuer-panel w-full md:w-1/2 p-4 space-y-3">
      <h2 className="text-xl font-bold mb-2">Issuance Panel <span className="text-sm text-gray-500">(Owner Only)</span></h2>
      <form onSubmit={issueCertificate} className="space-y-3">
        <input 
          type="text" 
          placeholder="Student Name" 
          value={studentName} 
          onChange={(e) => setStudentName(e.target.value)} 
          required 
          className="w-full p-2 border"
        />
        <input 
          type="text" 
          placeholder="Course Name" 
          value={courseName} 
          onChange={(e) => setCourseName(e.target.value)} 
          required 
          className="w-full p-2 border"
        />
        <input 
          type="date" 
          placeholder="Issue Date" 
          value={issueDate} 
          onChange={(e) => setIssueDate(e.target.value)} 
          required 
          className="w-full p-2 border"
        />
        <div className="p-2 border">
            <label className="block text-sm font-medium text-gray-700 mb-1">Select Certificate File (for IPFS):</label>
            <input 
                type="file" 
                onChange={(e) => setSelectedFile(e.target.files[0])} 
                required 
                className="w-full text-sm"
            />
        </div>
        <button 
          type="submit" 
          disabled={!certificateContract || !signer}
          className="w-full bg-green-500 hover:bg-green-600 text-white font-bold py-2 px-4 transition duration-300 disabled:bg-gray-400"
        >
          Issue Certificate & Record Hash
        </button>
      </form>
      {issuingStatus && <p className={`status mt-3 p-2 border text-sm ${issuingStatus.includes('Success') ? 'border-green-500 text-green-700' : issuingStatus.includes('Failed') ? 'border-red-500 text-red-700' : 'border-yellow-500 text-yellow-700'}`}>{issuingStatus}</p>}
    </div>
  );
  
  const renderVerifierPanel = () => (
    <div className="panel verifier-panel w-full md:w-1/2 p-4 space-y-3">
      <h2 className="text-xl font-bold mb-2">Certificate Verification</h2>
      <p className="mb-3 text-gray-600">Enter the IPFS Hash (CID) or the bytes32 Hash:</p>
      <form onSubmit={verifyCertificate} className="space-y-3">
        <input 
          type="text" 
          placeholder="IPFS Hash (CID) or Bytes32 Hash" 
          value={verifyHash} 
          onChange={(e) => setVerifyHash(e.target.value)} 
          required 
          className="w-full p-2 border"
        />
        <button 
          type="submit" 
          disabled={!certificateContract}
          className="w-full bg-purple-500 hover:bg-purple-600 text-white font-bold py-2 px-4 transition duration-300 disabled:bg-gray-400"
        >
          Verify on Blockchain
        </button>
      </form>
      
      {verificationResult && (
        <div className="verification-output mt-3 p-3 border space-y-2 text-sm">
          {verificationResult.status && <p className="text-yellow-700 font-medium">{verificationResult.status}</p>}
          {verificationResult.error && <p className="text-red-700 font-medium">Verification Error: {verificationResult.error}</p>}
          
          {verificationResult.isIssued === true && (
            <div className="success">
              <h3 className="font-bold text-green-600">✅ Verification Successful!</h3>
              <p>Name: <span className="font-semibold">{verificationResult.studentName}</span></p>
              <p>Course: <span className="font-semibold">{verificationResult.courseName}</span></p>
              <p>Date: <span className="font-semibold">{verificationResult.issueDate}</span></p>
              {verificationResult.ipfsHash !== 'Hash is bytes32' && (
                  <p className="text-blue-600 pt-2">
                      <a href={`https://gateway.pinata.cloud/ipfs/${verificationResult.ipfsHash}`} target="_blank" rel="noopener noreferrer">
                          Download Certificate (IPFS Link)
                      </a>
                  </p>
              )}
            </div>
          )}
          
          {verificationResult.isIssued === false && (
            <p className="failure text-red-700 font-medium">❌ Verification Failed: Hash **NOT** recorded on the blockchain.</p>
          )}
        </div>
      )}
    </div>
  );


  return (
    <div className="min-h-screen p-4 font-inter flex justify-center items-start">
      <script src="https://cdn.tailwindcss.com"></script>
      <div className="w-full max-w-4xl p-6 mt-8 space-y-6">
        <header className="text-center pb-4 border-b border-gray-300">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">🎓 Decentralized Certificate Issuer</h1>
          <p className="text-gray-600 mb-1">Connected Account: <span className="font-mono text-blue-600">{currentAccount || 'Not Connected'}</span></p>
          <p className="text-gray-600">Contract: <span className="font-mono text-blue-600">{contractAddress ? `${contractAddress.substring(0, 6)}...${contractAddress.slice(-4)}` : 'Loading Address'}</span></p>
        </header>
        
        {currentAccount ? (
          <div className="main-content flex flex-col md:flex-row justify-between gap-6">
            {renderIssuerPanel()}
            {renderVerifierPanel()}
          </div>
        ) : (
          <div className="text-center p-4">
            {renderConnectWalletButton()}
            <p className="mt-3 text-gray-500">Please connect your wallet to interact with the application.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;