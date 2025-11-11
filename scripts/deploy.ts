import * as hre from "hardhat"; 

async function main() {
  // Use 'any' type to resolve editor's red-line error for hre.ethers
  const ethers: any = hre.ethers; 
  
  // 1. Get the Contract Factory
  const CertificateFactory = await ethers.getContractFactory("Certificate");

  // 2. Deploy the Contract
  console.log("Deploying Certificate...");
  const certificate = await CertificateFactory.deploy();

  // 3. Wait for deployment to be confirmed
  await certificate.waitForDeployment();

  // 4. Log the deployed address
  const deployedAddress = await certificate.getAddress();
  console.log(
    `Certificate deployed to: ${deployedAddress}`
  );
}

// Execute the main function
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });