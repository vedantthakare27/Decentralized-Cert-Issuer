import React, { useState, useEffect, useCallback } from 'react';
import { BrowserProvider, Contract, ethers } from 'ethers'; 
import axios from 'axios';
import './App.css'; 

// Load ABI and Environment Variables
const contractABI = require('./utils/Certificate.json').abi;
const contractAddress = process.env.REACT_APP_CONTRACT_ADDRESS ? process.env.REACT_APP_CONTRACT_ADDRESS.trim() : null;
const pinataJwt = process.env.REACT_APP_PINATA_JWT;

// Define Sepolia Chain ID globally
const SEPOLIA_CHAIN_ID = 11155111; 

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
        // FIX: Ensure '0x' prefix is present but skip strict checksum validation
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
            // Suggesting network switch (if wallet supports)
            try {
                await ethereum.request({
                    method: 'wallet_switchEthereumChain',
                    params: [{ chainId: ethers.toQuantity(SEPOLIA_CHAIN_ID) }],
                });
            } catch (switchError) {
                console.warn("Could not auto-switch network:", switchError);
            }
            return false;
        }

        // 2. Create the provider with the network ID (Fixes UNCONFIGURED_NAME)
        const provider = new BrowserProvider(ethereum, currentChainId);
        
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
      if (!ethereum) return alert("Please install a wallet extension like Rabby or MetaMask.");

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
      // Specific error handling for the UNCONFIGURED_NAME issue
      if (error.code === 'UNCONFIGURED_NAME' || error.message.includes('network is not supported')) {
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

  // --- UI Rendering Functions ---

  const renderConnectWalletButton = () => (
    <button className="connect-button bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-6 rounded-xl shadow-lg transition duration-300 transform hover:scale-105" onClick={connectWallet}>
      Connect Wallet
    </button>
  );
  
  const renderIssuerPanel = () => (
    <div className="panel issuer-panel bg-white p-6 rounded-xl shadow-xl border border-blue-100 w-full md:w-5/12">
      <h2 className="text-2xl font-semibold mb-4 text-blue-800">Issuance Panel <span className="text-sm text-gray-500">(Owner Only)</span></h2>
      <form onSubmit={issueCertificate} className="space-y-4">
        <input 
          type="text" 
          placeholder="Student Name" 
          value={studentName} 
          onChange={(e) => setStudentName(e.target.value)} 
          required 
          className="w-full p-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
        />
        <input 
          type="text" 
          placeholder="Course Name" 
          value={courseName} 
          onChange={(e) => setCourseName(e.target.value)} 
          required 
          className="w-full p-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
        />
        <input 
          type="date" 
          placeholder="Issue Date" 
          value={issueDate} 
          onChange={(e) => setIssueDate(e.target.value)} 
          required 
          className="w-full p-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
        />
        <div className="border border-dashed border-gray-400 p-4 rounded-lg">
            <label className="block text-sm font-medium text-gray-700 mb-2">Select Certificate File (for IPFS):</label>
            <input 
                type="file" 
                onChange={(e) => setSelectedFile(e.target.files[0])} 
                required 
                className="w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
            />
        </div>
        <button 
          type="submit" 
          disabled={!certificateContract || !signer}
          className="w-full bg-green-500 hover:bg-green-600 text-white font-bold py-3 px-4 rounded-xl shadow-md transition duration-300 disabled:bg-gray-400"
        >
          Issue Certificate & Record Hash
        </button>
      </form>
      {issuingStatus && <p className={`status mt-4 p-3 rounded-lg ${issuingStatus.includes('Success') ? 'bg-green-100 text-green-700' : issuingStatus.includes('Failed') ? 'bg-red-100 text-red-700' : 'bg-yellow-100 text-yellow-700'}`}>{issuingStatus}</p>}
    </div>
  );
  
  const renderVerifierPanel = () => (
    <div className="panel verifier-panel bg-white p-6 rounded-xl shadow-xl border border-blue-100 w-full md:w-5/12">
      <h2 className="text-2xl font-semibold mb-4 text-blue-800">Certificate Verification</h2>
      <p className="mb-4 text-gray-600">Enter the IPFS Hash (CID) or the bytes32 Hash:</p>
      <form onSubmit={verifyCertificate} className="space-y-4">
        <input 
          type="text" 
          placeholder="IPFS Hash (CID) or Bytes32 Hash" 
          value={verifyHash} 
          onChange={(e) => setVerifyHash(e.target.value)} 
          required 
          className="w-full p-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
        />
        <button 
          type="submit" 
          disabled={!certificateContract}
          className="w-full bg-purple-500 hover:bg-purple-600 text-white font-bold py-3 px-4 rounded-xl shadow-md transition duration-300 disabled:bg-gray-400"
        >
          Verify on Blockchain
        </button>
      </form>
      
      {verificationResult && (
        <div className="verification-output mt-4 p-4 rounded-lg bg-gray-50 border">
          {verificationResult.status && <p className="text-yellow-700 font-medium">{verificationResult.status}</p>}
          {verificationResult.error && <p className="text-red-700 font-medium">Verification Error: {verificationResult.error}</p>}
          
          {verificationResult.isIssued === true && (
            <div className="success space-y-2">
              <h3 className="text-lg font-bold text-green-600">✅ Verification Successful!</h3>
              <p className="text-sm">The certificate hash is **valid and recorded**.</p>
              <p>Name: <span className="font-semibold text-gray-800">{verificationResult.studentName}</span></p>
              <p>Course: <span className="font-semibold text-gray-800">{verificationResult.courseName}</span></p>
              <p>Date: <span className="font-semibold text-gray-800">{verificationResult.issueDate}</span></p>
              {verificationResult.ipfsHash !== 'Hash is bytes32' && (
                  <p className="text-blue-600 hover:text-blue-800 font-medium pt-2">
                      <a href={`https://gateway.pinata.cloud/ipfs/${verificationResult.ipfsHash}`} target="_blank" rel="noopener noreferrer">
                          Download Certificate (IPFS Link)
                      </a>
                  </p>
              )}
            </div>
          )}
          
          {verificationResult.isIssued === false && (
            <p className="failure text-red-700 font-medium">❌ Verification Failed: This certificate hash is **NOT** recorded on the blockchain.</p>
          )}
        </div>
      )}
    </div>
  );


  return (
    <div className="min-h-screen bg-gray-100 p-4 font-inter flex justify-center items-start">
      <script src="https://cdn.tailwindcss.com"></script>
      <div className="w-full max-w-4xl bg-white p-8 rounded-2xl shadow-2xl border-t-8 border-blue-600 mt-8">
        <header className="text-center mb-8">
          <h1 className="text-4xl font-extrabold text-gray-900 mb-2">🎓 Decentralized Certificate Issuer</h1>
          <p className="text-gray-500 mb-1">Connected Account: <span className="font-mono text-blue-600">{currentAccount || 'Not Connected'}</span></p>
          <p className="text-gray-500">Contract: <span className="font-mono text-blue-600">{contractAddress ? `${contractAddress.substring(0, 6)}...${contractAddress.slice(-4)}` : 'Loading Address'}</span></p>
        </header>
        
        {currentAccount ? (
          <div className="main-content flex flex-col md:flex-row justify-between gap-6">
            {renderIssuerPanel()}
            {renderVerifierPanel()}
          </div>
        ) : (
          <div className="text-center">
            {renderConnectWalletButton()}
            <p className="mt-4 text-gray-500">Please connect your wallet to interact with the application.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
