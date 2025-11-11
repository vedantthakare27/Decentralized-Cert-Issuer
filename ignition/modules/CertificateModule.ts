import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

// We keep the original module ID "CounterModule" but change the deployment target.
export default buildModule("CounterModule", (m) => {
  // 1. Define the deployment action: Deploy the contract named "Certificate".
  // The contract name must match the contract name inside Certificate.sol
  const certificate = m.contract("Certificate", []);

  // 2. Return the deployed contract instance.
  return { certificate };
});