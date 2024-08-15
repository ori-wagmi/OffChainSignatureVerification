const { expect } = require("chai");

describe("Verify Contract", function () {
    let Verify;
    let owner;
    let addr1;
    let USDC = "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174";

    beforeEach(async function () {
        [owner, addr1] = await ethers.getSigners();
        const VerifyFactory = await ethers.getContractFactory("VerifySignature");
        Verify = await VerifyFactory.deploy(owner.address);
    });

    it("should set the correct public key", async function () {
        expect(await Verify.signer()).to.equal(owner.address);
    });

    it("Check signature", async function () {
        to = addr1.address;
        const amount = 999
        const name = "Hello"

        // Create and sign the message
        const hash = await Verify.getMessageHash(to, USDC, amount, name)
        const sig = await owner.signMessage(ethers.getBytes(hash))

        // console.log compare the signature with the expected signer
        const ethHash = await Verify.getEthSignedMessageHash(hash)
        console.log("owner          ", owner.address)
        console.log("recovered signer", await Verify.recoverSigner(ethHash, sig))

        // Correct signature and message returns true
        expect(
            await Verify.verify(to, USDC, amount, name, sig)
        ).to.equal(true)

        // Incorrect message returns false
        expect(
            await Verify.verify(to, USDC, amount + 1, name, sig)
        ).to.equal(false)

        // Incorrect message returns false
        expect(
            await Verify.verify(owner.address, USDC, amount, name, sig)
        ).to.equal(false)
    })
});