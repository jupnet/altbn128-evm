const hre = require("hardhat");

async function main() {
  console.log("Deploying AltBn128 contract...");

  const AltBn128 = await hre.ethers.getContractFactory("AltBn128");
  const altBn128 = await AltBn128.deploy();

  await altBn128.waitForDeployment();

  console.log(`AltBn128 deployed to: ${await altBn128.getAddress()}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });