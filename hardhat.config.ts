import { HardhatUserConfig } from "hardhat/config";
import "dotenv/config"; 
import "@nomicfoundation/hardhat-toolbox-mocha-ethers";

// 🚨 We import the module directly here 🚨
import hardhatIgnitionEthers from "@nomicfoundation/hardhat-ignition-ethers";

// Get the keys from the .env file
const SEPOLIA_RPC_URL = process.env.SEPOLIA_RPC_URL || "";
const PRIVATE_KEY = process.env.PRIVATE_KEY || "";

const config: HardhatUserConfig = {
  solidity: "0.8.20", 
  // 🚨 Explicitly define plugins here to solve HHE404 🚨
  plugins: [hardhatIgnitionEthers],
  networks: {
    sepolia: {
      url: SEPOLIA_RPC_URL,
      accounts: [PRIVATE_KEY],
      // FIX for HHE15 Error
      type: "http", 
    },
  },
};

export default config;