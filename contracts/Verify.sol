// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Copied from https://solidity-by-example.org/signature/
/* Signature Verification

How to Sign and Verify
# Signing
1. Create message to sign
2. Hash the message
3. Sign the hash (off chain, keep your private key secret)

# Verify
1. Recreate hash from the original message
2. Recover signer from signature and hash
3. Compare recovered signer to claimed signer
*/

contract VerifySignature {
    address public signer;

    constructor(address _signer) {
        signer = _signer;
    }

    // Constructs message hash to be signed.
    // Should be used by the frontend.
    function getMessageHash(
        address _to,
        address _paymentToken,
        uint256 _amount,
        string calldata _domainName
    ) public pure returns (bytes32) {
        bytes32 nameHash = computeNamehash(_domainName);
        return keccak256(abi.encodePacked(_to, _paymentToken, _amount, _domainName, nameHash));
    }

    // Constructs the signed message of the messageHash.
    // Wallets and ethers automatically appends "\x19Ethereum Signed Message\n" today.
    function getEthSignedMessageHash(bytes32 _messageHash)
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
        );
    }

    // Reconstructs ethSignedMessageHash and compares it to the given signature 
    function verify(
        address _to,
        address _paymentToken,
        uint256 _amount,
        string calldata _domainName,
        bytes memory signature
    ) public view returns (bool) {
        bytes32 messageHash = getMessageHash(_to, _paymentToken, _amount, _domainName);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        return recoverSigner(ethSignedMessageHash, signature) == signer;
    }

    // internal helper 
    function recoverSigner(
        bytes32 _ethSignedMessageHash,
        bytes memory _signature
    ) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }
    // internal helper
    function splitSignature(bytes memory sig)
        public
        pure
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }

    // https://eips.ethereum.org/EIPS/eip-137#namehash-algorithm
    // Note this assumes .hl TLD
    // name should be a single label
    function computeNamehash(string calldata _name) public pure returns (bytes32 namehash) {
        namehash = 0x0000000000000000000000000000000000000000000000000000000000000000;
        namehash = keccak256(
        abi.encodePacked(namehash, keccak256(abi.encodePacked('hl')))
        );
        namehash = keccak256(
        abi.encodePacked(namehash, keccak256(abi.encodePacked(_name)))
        );
    }
}
