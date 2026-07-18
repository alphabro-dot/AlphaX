'use client';

import { useState } from 'react';
import * as secp from '@noble/secp256k1';
import { keccak256 } from 'js-sha3';
import { ethers } from 'ethers';

export default function Home() {
  // Forward flow: private key -> public keys -> address
  const [privateKey, setPrivateKey] = useState('');
  const [compressedPubKey, setCompressedPubKey] = useState('');
  const [uncompressedPubKey, setUncompressedPubKey] = useState('');
  const [walletAddress, setWalletAddress] = useState('');
  const [calcDetails, setCalcDetails] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Backward (verification) flow: address + message + signature -> public key -> address check
  const [verifyAddress, setVerifyAddress] = useState('');
  const [verifyMessage, setVerifyMessage] = useState('');
  const [verifySignature, setVerifySignature] = useState('');
  const [verifyResult, setVerifyResult] = useState('');

  const convertKey = async () => {
    setLoading(true);
    setError('');
    setCompressedPubKey('');
    setUncompressedPubKey('');
    setWalletAddress('');
    setCalcDetails('');

    try {
      const cleanKey = privateKey.trim().replace(/^0x/i, '').toLowerCase();

      if (!/^[0-9a-f]{64}$/.test(cleanKey)) {
        throw new Error('Private key must be exactly 64 hexadecimal characters (32 bytes)');
      }

      const privBytes = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        privBytes[i] = parseInt(cleanKey.slice(i * 2, i * 2 + 2), 16);
      }

      const pubCompressed = secp.getPublicKey(privBytes, true);
      const pubUncompressed = secp.getPublicKey(privBytes, false);

      const compressedHex =
        '0x' +
        Array.from(pubCompressed)
          .map((byte) => byte.toString(16).padStart(2, '0'))
          .join('');

      const uncompressedHex =
        '0x' +
        Array.from(pubUncompressed)
          .map((byte) => byte.toString(16).padStart(2, '0'))
          .join('');

      const xHex = Array.from(pubUncompressed.slice(1, 33))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');

      const yHex = Array.from(pubUncompressed.slice(33))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');

      const xyBytes = pubUncompressed.slice(1);
      const hashHex = keccak256(xyBytes);
      const address = '0x' + hashHex.slice(-40);

      setCompressedPubKey(compressedHex);
      setUncompressedPubKey(uncompressedHex);
      setWalletAddress(address);

      const details =
        `1) Private key input
` +
        `   Hex: 0x${cleanKey}
` +
        `   Bytes: 32
` +
        `   Bits: 256

` +

        `2) Convert private key to secp256k1 public key
` +
        `   Operation: P = d × G
` +
        `   d = private key integer
` +
        `   G = generator point on secp256k1
` +
        `   Result = public key point (X, Y)

` +

        `3) Public key (compressed)
` +
        `   Format: 0x02/0x03 + X
` +
        `   Bytes: 33
` +
        `   Value: ${compressedHex}

` +

        `4) Public key (uncompressed)
` +
        `   Format: 0x04 + X + Y
` +
        `   Bytes: 65
` +
        `   Value: ${uncompressedHex}

` +

        `5) Split uncompressed public key
` +
        `   Prefix: 0x04
` +
        `   X: 0x${xHex}
` +
        `   Y: 0x${yHex}

` +

        `6) Ethereum / EVM address derivation
` +
        `   Input to Keccak-256: X || Y
` +
        `   Hash: ${hashHex}
` +
        `   Take last 20 bytes (last 40 hex chars)
` +
        `   Address: ${address}
`;

      setCalcDetails(details);
    } catch (err: any) {
      setError(err.message || 'Failed to generate keys');
    } finally {
      setLoading(false);
    }
  };

  // Backward check: wallet address + message + signature -> public key -> address match?
  const handleVerify = () => {
    try {
      setVerifyResult('');

      const addrInput = verifyAddress.trim();
      const msgInput = verifyMessage.trim();
      const sigInput = verifySignature.trim();

      if (!addrInput || !msgInput || !sigInput) {
        setVerifyResult('Please enter wallet address, message, and signature.');
        return;
      }

      const expectedAddress = addrInput.toLowerCase();

      // 1. Hash the message (Ethereum style)
const digest = ethers.hashMessage(msgInput);
const digestBytes = ethers.getBytes(digest);

      // 2. Recover public key and address from (digest, signature)
      const recoveredPubKey = ethers.recoverPublicKey(digestBytes, sigInput);
      const recoveredAddress = ethers.recoverAddress(digestBytes, sigInput).toLowerCase();

      // 3. Derive address from recovered public key via Keccak-256(X||Y)
      // recoveredPubKey is uncompressed: 0x04 + X + Y (65 bytes)
      const pubHex = recoveredPubKey.startsWith('0x') ? recoveredPubKey.slice(2) : recoveredPubKey;
      const pubHexNoPrefix = pubHex.startsWith('04') ? pubHex.slice(2) : pubHex;
      const pubBytes = ethers.getBytes('0x' + pubHexNoPrefix);
      const hashHex = keccak256(pubBytes);
      const derivedAddress = ('0x' + hashHex.slice(-40)).toLowerCase();

      const matchRecovered = recoveredAddress === expectedAddress;
      const matchDerived = derivedAddress === expectedAddress;

      let out =
        `1) Inputs
` +
        `   Wallet address: ${addrInput}
` +
        `   Message: "${msgInput}"
` +
        `   Signature: ${sigInput}

` +

        `2) Hash the message (Ethereum style)
` +
        `   digest = hashMessage(message)
` +
        `   digest: ${digest}

` +

        `3) ECDSA public key recovery
` +
        `   recoveredPublicKey = recoverPublicKey(digest, signature)
` +
        `   recoveredAddress  = recoverAddress(digest, signature)
` +
        `   Recovered public key: ${recoveredPubKey}
` +
        `   Recovered address from signature: ${recoveredAddress}

` +

        `4) Derive address from recovered public key
` +
        `   Drop 0x04 prefix from uncompressed public key -> X || Y (64 bytes)
` +
        `   Keccak-256(X || Y) = ${hashHex}
` +
        `   Last 20 bytes -> derived address = ${derivedAddress}

` +

        `5) Compare with input address
` +
        `   Expected address: ${expectedAddress}
` +
        `   Match recoveredAddress? ${matchRecovered ? 'YES' : 'NO'}
` +
        `   Match derivedAddress?  ${matchDerived ? 'YES' : 'NO'}
`;

      if (matchRecovered && matchDerived) {
        out += `

Result: ✅ The recovered public key corresponds to the given wallet address.
`;
      } else {
        out += `

Result: ❌ The signature does NOT belong to the given wallet address.
`;
      }

      setVerifyResult(out);
    } catch (err: any) {
      setVerifyResult(`Verification failed: ${err.message || String(err)}`);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-white flex items-center justify-center p-4">
      <div className="max-w-3xl w-full bg-gray-900 rounded-2xl p-8 shadow-xl space-y-10">
        <h1 className="text-3xl font-bold text-center">
          secp256k1 Key Tool
        </h1>
        <p className="text-gray-400 text-center">
          Box 1: Private Key → Public Keys → Wallet Address • Box 2: Wallet Address + Message + Signature → Public Key → Address Check
        </p>

        {/* Box 1: Forward direction */}
        <div className="space-y-6 bg-gray-900 border border-gray-800 p-6 rounded-2xl">
          <h2 className="text-lg font-semibold text-center">
            Box 1 — Private Key → Public Key → Address
          </h2>

          <div>
            <label className="block text-sm font-medium mb-2 text-gray-300">
              Private Key (hex)
            </label>
            <textarea
              value={privateKey}
              onChange={(e) => setPrivateKey(e.target.value)}
              placeholder="Enter 64 hex characters (example: 7311a79aed7b4d686a39c441bec87ed133fb57c08ea43b0860b1a0100b7b7527)"
              className="w-full h-28 bg-gray-800 border border-gray-700 rounded-xl px-4 py-3 text-sm font-mono focus:outline-none focus:border-blue-500 resize-y"
            />
          </div>

          <button
            onClick={convertKey}
            disabled={loading || !privateKey.trim()}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 py-3 rounded-xl font-semibold transition disabled:cursor-not-allowed"
          >
            {loading ? 'Generating...' : 'Generate Keys'}
          </button>

          {error && (
            <div className="bg-red-900/50 border border-red-700 text-red-300 p-4 rounded-xl text-sm">
              {error}
            </div>
          )}

          {compressedPubKey && (
            <div className="grid gap-4 md:grid-cols-2">
              <div className="bg-emerald-950 border border-emerald-800 p-5 rounded-xl">
                <div className="text-emerald-400 text-sm mb-2">
                  Public Key (Compressed)
                </div>
                <div className="font-mono break-all text-emerald-100 text-sm leading-relaxed">
                  {compressedPubKey}
                </div>
              </div>

              <div className="bg-emerald-950 border border-emerald-800 p-5 rounded-xl">
                <div className="text-emerald-400 text-sm mb-2">
                  Wallet Address
                </div>
                <div className="font-mono break-all text-emerald-100 text-sm leading-relaxed">
                  {walletAddress}
                </div>
              </div>
            </div>
          )}

          {uncompressedPubKey && (
            <div className="bg-indigo-950 border border-indigo-800 p-5 rounded-xl">
              <div className="text-indigo-400 text-sm mb-2">
                Public Key (Uncompressed)
              </div>
              <div className="font-mono break-all text-indigo-100 text-sm leading-relaxed">
                {uncompressedPubKey}
              </div>
            </div>
          )}

          {calcDetails && (
            <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl">
              <div className="text-sm font-semibold mb-3 text-gray-300">
                Calculation Steps (Forward)
              </div>
              <pre className="text-xs text-gray-200 font-mono whitespace-pre-wrap break-words leading-relaxed">
                {calcDetails}
              </pre>
            </div>
          )}
        </div>

        {/* Box 2: Backward verification */}
        <div className="space-y-6 bg-gray-900 border border-gray-800 p-6 rounded-2xl">
          <h2 className="text-lg font-semibold text-center">
            Box 2 — Wallet Address + Message + Signature → Public Key → Address Check
          </h2>
          <p className="text-xs text-gray-400 text-center">
            This box recovers the public key from a signed message (ECDSA) and verifies that it corresponds to the wallet address.
          </p>

          <div className="space-y-3">
            <label className="block text-sm font-medium text-gray-300">
              Wallet Address (0x...)
            </label>
            <input
              value={verifyAddress}
              onChange={(e) => setVerifyAddress(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-xl px-4 py-2 text-sm font-mono focus:outline-none focus:border-blue-500"
              placeholder="0xYourWalletAddress"
            />

            <label className="block text-sm font-medium text-gray-300">
              Message (exact string that was signed)
            </label>
            <textarea
              value={verifyMessage}
              onChange={(e) => setVerifyMessage(e.target.value)}
              className="w-full h-20 bg-gray-800 border border-gray-700 rounded-xl px-4 py-2 text-sm font-mono focus:outline-none focus:border-blue-500 resize-y"
              placeholder="Hello from my key tool!"
            />

            <label className="block text-sm font-medium text-gray-300">
              Signature (hex)
            </label>
            <textarea
              value={verifySignature}
              onChange={(e) => setVerifySignature(e.target.value)}
              className="w-full h-20 bg-gray-800 border border-gray-700 rounded-xl px-4 py-2 text-sm font-mono focus:outline-none focus:border-blue-500 resize-y"
              placeholder="0x..."
            />

            <button
              onClick={handleVerify}
              className="w-full bg-emerald-600 hover:bg-emerald-700 py-3 rounded-xl font-semibold transition"
            >
              Verify Public Key & Address
            </button>

            {verifyResult && (
              <div className="mt-3 bg-gray-950 border border-gray-800 p-4 rounded-xl">
                <div className="text-sm font-semibold mb-2 text-gray-300">
                  Calculation Steps (Backward / ECDSA Recovery)
                </div>
                <pre className="text-xs text-gray-200 font-mono whitespace-pre-wrap break-words leading-relaxed">
                  {verifyResult}
                </pre>
              </div>
            )}
          </div>
        </div>

        <div className="text-center text-xs text-gray-500">
          Runs 100% in your browser • No data leaves your device
        </div>
      </div>
    </div>
  );
}
