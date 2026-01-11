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
        "0x25e44334e21624b7626ae9bb677c6e14e216e9a2c33b55d9a21881c4a25f72fc21ef598efec38778e5cf284e8a7637686924a539c51409f6d83649e509b558701a38ebfa252e592a01db69a6cff97e1d9204a1f099849479e59e62a5f7674c1f168a6fbdad30bbd50251b33f8f2953f5f3319444a4b2a601f9cf695d5dd9213e";
      const signature =
        "0x1910db7b05d0d1c94c4a4bc98b8022dbe1db5cc0feab1923428fa54225b0f6be114476b46f635e3e70e86a7c74ee71866ee6eb9542b38db1e6694d2ea8ca8ff4"; // 64 bytes

      await expect(altBn128.verifySignature(hash, validPubkey, signature)).to
        .eventually.be.true;
    });

    it("Should succeed but failing", async function () {
      const { altBn128 } = await loadFixture(deployAltBn128Fixture);

      const hash =
        "0x634ba9c05eed0b2cfc51c1b30b4320e4fdc8a5d3958a959317e576d811dbcd7f";
      const validPubkey =
        "0xa5e44334e21624b7626ae9bb677c6e14e216e9a2c33b55d9a21881c4a25f72fc21ef598efec38778e5cf284e8a7637686924a539c51409f6d83649e509b558701a38ebfa252e592a01db69a6cff97e1d9204a1f099849479e59e62a5f7674c1f168a6fbdad30bbd50251b33f8f2953f5f3319444a4b2a601f9cf695d5dd9213e";
      const signature =
        "0x1910db7b05d0d1c94c4a4bc98b8022dbe1db5cc0feab1923428fa54225b0f6be114476b46f635e3e70e86a7c74ee71866ee6eb9542b38db1e6694d2ea8ca8ff4"; // 64 bytes

      await expect(altBn128.verifySignature(hash, validPubkey, signature)).to
        .eventually.be.true;
    });

    it("Should succeed", async function () {
      const { altBn128 } = await loadFixture(deployAltBn128Fixture);

      const hash =
        "0x61e768845b16857a4370fed281f65f244efd9ee955487a3414cc0d60cd759536";
      const validPubkey =
        "0x25e44334e21624b7626ae9bb677c6e14e216e9a2c33b55d9a21881c4a25f72fc21ef598efec38778e5cf284e8a7637686924a539c51409f6d83649e509b558701a38ebfa252e592a01db69a6cff97e1d9204a1f099849479e59e62a5f7674c1f168a6fbdad30bbd50251b33f8f2953f5f3319444a4b2a601f9cf695d5dd9213e";
      const signature =
        "0x2402c94ba547b6af4d765a730b1afca09ecf116e1a80f0d8c543ce475c076f350a5cf346c9996dfa55876bc975720f0ddcce4b650da483a448a43b008f14b2fe"; // 64 bytes

      await expect(altBn128.verifySignature(hash, validPubkey, signature)).to
        .eventually.be.true;
    });

    it("Should succeed but failing", async function () {
      const { altBn128 } = await loadFixture(deployAltBn128Fixture);

      const hash =
        "0x61e768845b16857a4370fed281f65f244efd9ee955487a3414cc0d60cd759536";
      const validPubkey =
        "0xa5e44334e21624b7626ae9bb677c6e14e216e9a2c33b55d9a21881c4a25f72fc21ef598efec38778e5cf284e8a7637686924a539c51409f6d83649e509b558701a38ebfa252e592a01db69a6cff97e1d9204a1f099849479e59e62a5f7674c1f168a6fbdad30bbd50251b33f8f2953f5f3319444a4b2a601f9cf695d5dd9213e";
      const signature =
        "0x2402c94ba547b6af4d765a730b1afca09ecf116e1a80f0d8c543ce475c076f350a5cf346c9996dfa55876bc975720f0ddcce4b650da483a448a43b008f14b2fe"; // 64 bytes

      await expect(altBn128.verifySignature(hash, validPubkey, signature)).to
        .eventually.be.true;
    });

    it("Should succeed but failing", async function () {
      const { altBn128 } = await loadFixture(deployAltBn128Fixture);

      const hash =
        "0x1b77a999f2ee6dfdec2c36b00605f62717d8f2cd2df9b8907f885f89a4c8d8b5";
      const validPubkey =
        "0x25e44334e21624b7626ae9bb677c6e14e216e9a2c33b55d9a21881c4a25f72fc21ef598efec38778e5cf284e8a7637686924a539c51409f6d83649e509b558701a38ebfa252e592a01db69a6cff97e1d9204a1f099849479e59e62a5f7674c1f168a6fbdad30bbd50251b33f8f2953f5f3319444a4b2a601f9cf695d5dd9213e";
      const signature =
        "0x02e6e34393dab4e3b036acf7db7e9cbd4aa61bea998aded77a3ab52135e1a69427601844924cb483ce078d8778f81831c223a813c48572775795f2d63e4019d5"; // 64 bytes

      await expect(altBn128.verifySignature(hash, validPubkey, signature)).to
        .eventually.be.true;
    });

    it("Should succeed but failing", async function () {
      const { altBn128 } = await loadFixture(deployAltBn128Fixture);

      const hash =
        "0x1b77a999f2ee6dfdec2c36b00605f62717d8f2cd2df9b8907f885f89a4c8d8b5";
      const validPubkey =
        "0xa5e44334e21624b7626ae9bb677c6e14e216e9a2c33b55d9a21881c4a25f72fc21ef598efec38778e5cf284e8a7637686924a539c51409f6d83649e509b558701a38ebfa252e592a01db69a6cff97e1d9204a1f099849479e59e62a5f7674c1f168a6fbdad30bbd50251b33f8f2953f5f3319444a4b2a601f9cf695d5dd9213e";
      const signature =
        "0x02e6e34393dab4e3b036acf7db7e9cbd4aa61bea998aded77a3ab52135e1a69427601844924cb483ce078d8778f81831c223a813c48572775795f2d63e4019d5"; // 64 bytes

      await expect(altBn128.verifySignature(hash, validPubkey, signature)).to
        .eventually.be.true;
    });

    // it("Should succeed", async function () {
    //   const { altBn128 } = await loadFixture(deployAltBn128Fixture);

    //   const hash =
    //     "0x634ba9c05eed0b2cfc51c1b30b4320e4fdc8a5d3958a959317e576d811dbcd7f";
    //   const validPubkey =
    //     "0x046020e1ad8094d79838eef8c3e42c8a15d01fe56881c0f87e618a5a0119518c266905b38de07d87fcdb612618615b25f71a7ee8e477c52b99fa26a6d5d02ee404a7f06de83e92b329a8e0e07eb4970087bb7c9c889cb5309f012c73f8016dce0b193a88dc1b930cb47d8628ffad3afe3a9578ed87f7e946665ec4e16787c6f8";
    //   const signature =
    //     "0x037a008564196a6bacc191070114642f4861c4e6c13c44a07740c528bb080c63268c4624abfbcce1545b74957095bdf88b5d8c3c7b2c726aceda28e2bc2381b6"; // 64 bytes

    //   await expect(altBn128.verifySignature(hash, validPubkey, signature)).to
    //     .eventually.be.true;
    // });

    // it("Should succeed but failing", async function () {
    //   const { altBn128 } = await loadFixture(deployAltBn128Fixture);

    //   const hash =
    //     "0x1b77a999f2ee6dfdec2c36b00605f62717d8f2cd2df9b8907f885f89a4c8d8b5";
    //   const validPubkey =
    //     "0x046020e1ad8094d79838eef8c3e42c8a15d01fe56881c0f87e618a5a0119518c266905b38de07d87fcdb612618615b25f71a7ee8e477c52b99fa26a6d5d02ee404a7f06de83e92b329a8e0e07eb4970087bb7c9c889cb5309f012c73f8016dce0b193a88dc1b930cb47d8628ffad3afe3a9578ed87f7e946665ec4e16787c6f8";
    //   const signature =
    //     "0x2f86f6b53ad8ea148a235044acf72ef7b6c6d2974d5503de3284fe6887450c86278ca08ebd4abdd08109ba09f2111ac2ae4570ab8bcee806d9607758bfde04c2"; // 64 bytes

    //   await expect(altBn128.verifySignature(hash, validPubkey, signature)).to
    //     .eventually.be.true;
    // });

    // it("Should succeed but failing", async function () {
    //   const { altBn128 } = await loadFixture(deployAltBn128Fixture);

    //   const hash =
    //     "0xf55cad412c9c5a512301b809c228bd8b0fa1853a1cf38a14ae3c5d7ec3001830";
    //   const validPubkey =
    //     "0x046020e1ad8094d79838eef8c3e42c8a15d01fe56881c0f87e618a5a0119518c266905b38de07d87fcdb612618615b25f71a7ee8e477c52b99fa26a6d5d02ee404a7f06de83e92b329a8e0e07eb4970087bb7c9c889cb5309f012c73f8016dce0b193a88dc1b930cb47d8628ffad3afe3a9578ed87f7e946665ec4e16787c6f8";
    //   const signature =
    //     "0x214e6d646ef65ad3b0e9b5ca15927b61d5cdf5638a97c904a0a10cf6e51d6ddf2592d4595b6ecbfce779f3d57e230d945fd3df632c57698ac4ec7971a46d7f68"; // 64 bytes

    //   await expect(altBn128.verifySignature(hash, validPubkey, signature)).to
    //     .eventually.be.true;
    // });

    // it("Should succeed but failing", async function () {
    //   const { altBn128 } = await loadFixture(deployAltBn128Fixture);

    //   const hash =
    //     "0x5bf5f7e1de83a706a19a3c56a5d22157d8e8b07fa2dcef88bae6fc24075e7821";
    //   const validPubkey =
    //     "0x046020e1ad8094d79838eef8c3e42c8a15d01fe56881c0f87e618a5a0119518c266905b38de07d87fcdb612618615b25f71a7ee8e477c52b99fa26a6d5d02ee404a7f06de83e92b329a8e0e07eb4970087bb7c9c889cb5309f012c73f8016dce0b193a88dc1b930cb47d8628ffad3afe3a9578ed87f7e946665ec4e16787c6f8";
    //   const signature =
    //     "0x0ef073758583a9751b7810f0b9ded47e3dbea7f771db275978d7e2a170ad299c20048c0b4cb212316e10f82acc56052767cc5d4c4a99fb549e6eaebceb167898"; // 64 bytes

    //   await expect(altBn128.verifySignature(hash, validPubkey, signature)).to
    //     .eventually.be.true;
    // });
  });
});
