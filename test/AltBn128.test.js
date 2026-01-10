const { expect } = require("chai");
const { ethers } = require("hardhat");
const {
  loadFixture,
} = require("@nomicfoundation/hardhat-toolbox/network-helpers");

describe("AltBn128", function () {
  async function deployAltBn128Fixture() {
    const [owner, otherAccount] = await ethers.getSigners();

    const AltBn128 = await ethers.getContractFactory("AltBn128");
    const altBn128 = await AltBn128.deploy();

    return { altBn128, owner, otherAccount };
  }

  describe("Deployment", function () {
    it("Should deploy successfully", async function () {
      const { altBn128 } = await loadFixture(deployAltBn128Fixture);
      expect(altBn128.target).to.be.properAddress;
    });
  });

  describe("VerifySignature", function () {
    it("Should succeed", async function () {
      const { altBn128 } = await loadFixture(deployAltBn128Fixture);

      const hash =
        "0x634ba9c05eed0b2cfc51c1b30b4320e4fdc8a5d3958a959317e576d811dbcd7f";
      const validPubkey =
        "0x046020e1ad8094d79838eef8c3e42c8a15d01fe56881c0f87e618a5a0119518c266905b38de07d87fcdb612618615b25f71a7ee8e477c52b99fa26a6d5d02ee404a7f06de83e92b329a8e0e07eb4970087bb7c9c889cb5309f012c73f8016dce0b193a88dc1b930cb47d8628ffad3afe3a9578ed87f7e946665ec4e16787c6f8";
      const signature =
        "0x037a008564196a6bacc191070114642f4861c4e6c13c44a07740c528bb080c63268c4624abfbcce1545b74957095bdf88b5d8c3c7b2c726aceda28e2bc2381b6"; // 64 bytes

      await expect(altBn128.verifySignature(hash, validPubkey, signature)).to
        .eventually.be.true;
    });

    it("Should succeed but failing", async function () {
      const { altBn128 } = await loadFixture(deployAltBn128Fixture);

      const hash =
        "0x1b77a999f2ee6dfdec2c36b00605f62717d8f2cd2df9b8907f885f89a4c8d8b5";
      const validPubkey =
        "0x046020e1ad8094d79838eef8c3e42c8a15d01fe56881c0f87e618a5a0119518c266905b38de07d87fcdb612618615b25f71a7ee8e477c52b99fa26a6d5d02ee404a7f06de83e92b329a8e0e07eb4970087bb7c9c889cb5309f012c73f8016dce0b193a88dc1b930cb47d8628ffad3afe3a9578ed87f7e946665ec4e16787c6f8";
      const signature =
        "0x2f86f6b53ad8ea148a235044acf72ef7b6c6d2974d5503de3284fe6887450c86278ca08ebd4abdd08109ba09f2111ac2ae4570ab8bcee806d9607758bfde04c2"; // 64 bytes

      await expect(altBn128.verifySignature(hash, validPubkey, signature)).to
        .eventually.be.true;
    });

    it("Should succeed but failing", async function () {
      const { altBn128 } = await loadFixture(deployAltBn128Fixture);

      const hash =
        "0xf55cad412c9c5a512301b809c228bd8b0fa1853a1cf38a14ae3c5d7ec3001830";
      const validPubkey =
        "0x046020e1ad8094d79838eef8c3e42c8a15d01fe56881c0f87e618a5a0119518c266905b38de07d87fcdb612618615b25f71a7ee8e477c52b99fa26a6d5d02ee404a7f06de83e92b329a8e0e07eb4970087bb7c9c889cb5309f012c73f8016dce0b193a88dc1b930cb47d8628ffad3afe3a9578ed87f7e946665ec4e16787c6f8";
      const signature =
        "0x214e6d646ef65ad3b0e9b5ca15927b61d5cdf5638a97c904a0a10cf6e51d6ddf2592d4595b6ecbfce779f3d57e230d945fd3df632c57698ac4ec7971a46d7f68"; // 64 bytes

      await expect(altBn128.verifySignature(hash, validPubkey, signature)).to
        .eventually.be.true;
    });

    it("Should succeed but failing", async function () {
      const { altBn128 } = await loadFixture(deployAltBn128Fixture);

      const hash =
        "0x5bf5f7e1de83a706a19a3c56a5d22157d8e8b07fa2dcef88bae6fc24075e7821";
      const validPubkey =
        "0x046020e1ad8094d79838eef8c3e42c8a15d01fe56881c0f87e618a5a0119518c266905b38de07d87fcdb612618615b25f71a7ee8e477c52b99fa26a6d5d02ee404a7f06de83e92b329a8e0e07eb4970087bb7c9c889cb5309f012c73f8016dce0b193a88dc1b930cb47d8628ffad3afe3a9578ed87f7e946665ec4e16787c6f8";
      const signature =
        "0x0ef073758583a9751b7810f0b9ded47e3dbea7f771db275978d7e2a170ad299c20048c0b4cb212316e10f82acc56052767cc5d4c4a99fb549e6eaebceb167898"; // 64 bytes

      await expect(altBn128.verifySignature(hash, validPubkey, signature)).to
        .eventually.be.true;
    });
  });
});
