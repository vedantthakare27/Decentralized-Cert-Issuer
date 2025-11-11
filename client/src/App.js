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

  /**
   * Final, robust function to connect wallet, check network, and set up signer/provider.
   * This uses the confirmed Chain ID directly in BrowserProvider for maximum stability.
   */
  const setupWalletAndSigner = useCallback(async (ethereum, accounts) => {
    try {
        // 1. Check current network Chain ID from the wallet
        const chainIdHex = await ethereum.request({ method: 'eth_chainId' });
        const currentChainId = parseInt(chainIdHex, 16);

        if (currentChainId !== SEPOLIA_CHAIN_ID) {
            setIssuingStatus('Please switch Rabby Wallet to the Sepolia Test Network (Chain ID: 11155111).');
            return false;
        }

        // 2. ULTIMATE FIX: Create the provider explicitly passing the currentChainId (11155111)
        // This bypasses potential "UNCONFIGURED_NAME" and "custom network" errors from the wallet provider.
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
      // Defensive check before transaction
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

  // --- UI Rendering Functions (Professional Styling Restored) ---

  const renderConnectWalletButton = () => (
    <button className="connect-button w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 px-4 rounded-xl shadow-lg transition duration-300 transform hover:scale-[1.01]" onClick={connectWallet}>
      Connect Wallet
    </button>
  );
  
  const renderIssuerPanel = () => (
    <div className="panel issuer-panel bg-white p-6 rounded-2xl shadow-xl w-full md:w-1/2 transition duration-300 hover:shadow-2xl">
      <h2 className="text-2xl font-extrabold mb-4 text-indigo-700 border-b pb-2">Issuance Panel <span className="text-sm text-gray-500 font-normal">(Owner Only)</span></h2>
      <form onSubmit={issueCertificate} className="space-y-4">
        <input 
          type="text" 
          placeholder="Student Name" 
          value={studentName} 
          onChange={(e) => setStudentName(e.target.value)} 
          required 
          className="w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500 transition duration-150"
        />
        <input 
          type="text" 
          placeholder="Course Name" 
          value={courseName} 
          onChange={(e) => setCourseName(e.target.value)} 
          required 
          className="w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500 transition duration-150"
        />
        <input 
          type="date" 
          placeholder="Issue Date" 
          value={issueDate} 
          onChange={(e) => setIssueDate(e.target.value)} 
          required 
          className="w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500 transition duration-150"
        />
        <div className="p-3 border border-gray-300 rounded-lg bg-gray-50">
            <label className="block text-sm font-medium text-gray-700 mb-1">Select Certificate File (for IPFS):</label>
            <input 
                type="file" 
                onChange={(e) => setSelectedFile(e.target.files[0])} 
                required 
                className="w-full text-sm text-gray-500 mt-2"
            />
        </div>
        <button 
          type="submit" 
          disabled={!certificateContract || !signer}
          className="w-full bg-green-500 hover:bg-green-600 text-white font-bold py-3 px-4 rounded-lg shadow-md transition duration-300 disabled:bg-gray-400 disabled:shadow-none"
        >
          Issue Certificate & Record Hash
        </button>
      </form>
      {issuingStatus && <p className={`status mt-4 p-3 rounded-lg text-sm font-medium ${issuingStatus.includes('Success') ? 'bg-green-100 text-green-700 border border-green-300' : issuingStatus.includes('Failed') ? 'bg-red-100 text-red-700 border border-red-300' : 'bg-yellow-100 text-yellow-700 border border-yellow-300'}`}>{issuingStatus}</p>}
    </div>
  );
  
  const renderVerifierPanel = () => (
    <div className="panel verifier-panel bg-white p-6 rounded-2xl shadow-xl w-full md:w-1/2 transition duration-300 hover:shadow-2xl">
      <h2 className="text-2xl font-extrabold mb-4 text-purple-700 border-b pb-2">Certificate Verification</h2>
      <p className="mb-4 text-gray-600">Enter the IPFS Hash (CID) or the bytes32 Hash:</p>
      <form onSubmit={verifyCertificate} className="space-y-4">
        <input 
          type="text" 
          placeholder="IPFS Hash (CID) or Bytes32 Hash" 
          value={verifyHash} 
          onChange={(e) => setVerifyHash(e.target.value)} 
          required 
          className="w-full p-3 border border-gray-300 rounded-lg focus:ring-purple-500 focus:border-purple-500 transition duration-150"
        />
        <button 
          type="submit" 
          disabled={!certificateContract}
          className="w-full bg-purple-600 hover:bg-purple-700 text-white font-bold py-3 px-4 rounded-lg shadow-md transition duration-300 disabled:bg-gray-400 disabled:shadow-none"
        >
          Verify on Blockchain
        </button>
      </form>
      
      {verificationResult && (
        <div className="verification-output mt-4 p-4 rounded-lg bg-gray-50 border space-y-2 text-sm">
          {verificationResult.status && <p className="text-yellow-700 font-medium">{verificationResult.status}</p>}
          {verificationResult.error && <p className="text-red-700 font-medium">Verification Error: {verificationResult.error}</p>}
          
          {verificationResult.isIssued === true && (
            <div className="success border-l-4 border-green-500 pl-3 pt-1">
              <h3 className="font-bold text-green-600 text-lg">✅ Verification Successful!</h3>
              <p>Name: <span className="font-semibold">{verificationResult.studentName}</span></p>
              <p>Course: <span className="font-semibold">{verificationResult.courseName}</span></p>
              <p>Date: <span className="font-semibold">{verificationResult.issueDate}</span></p>
              {verificationResult.ipfsHash !== 'Hash is bytes32' && (
                  <p className="text-blue-600 pt-2">
                      <a href={`https://gateway.pinata.cloud/ipfs/${verificationResult.ipfsHash}`} target="_blank" rel="noopener noreferrer" className="hover:underline">
                          View Certificate on IPFS
                      </a>
                  </p>
              )}
            </div>
          )}
          
          {verificationResult.isIssued === false && (
            <p className="failure text-red-700 font-medium border-l-4 border-red-500 pl-3 pt-1">❌ Verification Failed: Hash **NOT** recorded on the blockchain.</p>
          )}
        </div>
      )}
    </div>
  );


  return (
    <div className="min-h-screen bg-gray-100 p-8 font-inter flex justify-center items-start">
      <script src="https://cdn.tailwindcss.com"></script>
      <div className="w-full max-w-5xl bg-white p-8 rounded-3xl shadow-2xl mt-8 space-y-8">
        <header className="text-center pb-6 border-b-2 border-indigo-200">
          <h1 className="text-4xl font-black text-indigo-800 mb-2">🎓 Decentralized Certificate Issuer</h1>
          <div className="flex justify-center space-x-6 text-gray-600 text-md">
            <p>Account: <span className="font-mono text-indigo-600">{currentAccount || 'Not Connected'}</span></p>
            <p>Contract: <span className="font-mono text-indigo-600">{contractAddress ? `${contractAddress.substring(0, 6)}...${contractAddress.slice(-4)}` : 'Loading Address'}</span></p>
          </div>
        </header>
        
        {currentAccount ? (
          <div className="main-content flex flex-col md:flex-row justify-between gap-8">
            {renderIssuerPanel()}
            {renderVerifierPanel()}
          </div>
        ) : (
          <div className="text-center p-8 bg-gray-50 rounded-xl shadow-inner">
            {renderConnectWalletButton()}
            <p className="mt-4 text-gray-500 text-lg">Connect your wallet (Rabby recommended) to start interacting with the DApp on **Sepolia**.</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
