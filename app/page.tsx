'use client';

import { useState } from 'react';
import { ethers, Transaction, Signature as EthersSignature } from 'ethers';
import * as secp from '@noble/secp256k1';
import { keccak256 } from 'js-sha3';

type ChainKey = 'ethereum' | 'bsc';

const RPC_URLS: Record<ChainKey, string> = {
  ethereum: 'https://ethereum.publicnode.com',
  bsc: 'https://bsc.publicnode.com',
};

const CHAIN_LABELS: Record<ChainKey, string> = {
  ethereum: 'Ethereum Mainnet',
  bsc: 'BNB Smart Chain',
};

// Simple helper to convert 0x... hex to bigint
function hexToBigInt(hex: string): bigint {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  return BigInt('0x' + clean);
}

// Standard ECDSA public key recovery using @noble/secp256k1 v2
// msgHash: 32 bytes
// signature: { r, s } as bigint
// recovery: 0 or 1
// returns uncompressed public key bytes (65 bytes)
function recoverPublicKeyFromSignature(
  msgHash: Uint8Array,
  signature: { r: bigint; s: bigint },
  recovery: number
): Uint8Array {
  if (msgHash.length !== 32) {
    throw new Error('msgHash must be 32 bytes');
  }

  const sig = new secp.Signature(signature.r, signature.s, recovery);
  const point = sig.recoverPublicKey(msgHash);
  const pubBytes = point.toRawBytes(false); // false = uncompressed (0x04 || x || y)
  return pubBytes;
}

export default function Home() {
  // Box 1 (R&D) – Private key -> Public key -> Address
  const [privKeyInput, setPrivKeyInput] = useState('');
  const [box1PubKeyUncompressed, setBox1PubKeyUncompressed] = useState('');
  const [box1PubKeyCompressed, setBox1PubKeyCompressed] = useState('');
  const [box1Address, setBox1Address] = useState('');
  const [box1Error, setBox1Error] = useState('');

  // Box 3 – Chain + tx hash -> v/r/s -> Public key -> Address check
  const [chain, setChain] = useState<ChainKey>('ethereum');
  const [txHash, setTxHash] = useState('');
  const [txJson, setTxJson] = useState<any | null>(null);
  const [box3Result, setBox3Result] = useState('');
  const [txError, setTxError] = useState('');
  const [txLoading, setTxLoading] = useState(false);

  // ---------------- Box 1: Private key -> Public key -> Address (R&D only) ----------------

  const handleBox1 = async () => {
    setBox1Error('');
    setBox1PubKeyUncompressed('');
    setBox1PubKeyCompressed('');
    setBox1Address('');

    try {
      const clean = privKeyInput.trim().replace(/^0x/i, '').toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(clean)) {
        throw new Error('Private key must be 64 hex characters (32 bytes).');
      }

      const privBytes = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        privBytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
      }

      // Uncompressed public key
      const pubUncompressed = secp.getPublicKey(privBytes, false);
      const pubHexUncompressed =
        '0x' +
        Array.from(pubUncompressed)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');

      // Compressed public key
      const pubCompressed = secp.getPublicKey(privBytes, true);
      const pubHexCompressed =
        '0x' +
        Array.from(pubCompressed)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');

      const hashHex = keccak256(pubUncompressed.slice(1));
      const address = '0x' + hashHex.slice(-40);

      setBox1PubKeyUncompressed(pubHexUncompressed);
      setBox1PubKeyCompressed(pubHexCompressed);
      setBox1Address(address);
    } catch (err: any) {
      setBox1Error(err?.message || 'Failed to derive public key and address.');
    }
  };

  // ---------------- Box 3: Transaction v/r/s -> Public key -> Address check ----------------

  const handleBox3 = async () => {
    setTxLoading(true);
    setTxError('');
    setTxJson(null);
    setBox3Result('');

    try {
      const cleanHash = txHash.trim();
      if (!/^0x[a-fA-F0-9]{64}$/.test(cleanHash)) {
        throw new Error('Transaction hash must be 66 hex characters starting with 0x.');
      }

      const provider = new ethers.JsonRpcProvider(RPC_URLS[chain]);
      const txResp = await provider.getTransaction(cleanHash);

      if (!txResp) {
        throw new Error(`Transaction not found on ${CHAIN_LABELS[chain]}.`);
      }

      setTxJson(txResp);

      if (!txResp.signature || txResp.signature.r === '0x' || txResp.signature.s === '0x') {
        throw new Error('Transaction does not have a usable v/r/s signature.');
      }

      // Build a Transaction object from the response fields (without signature)
      const tx = Transaction.from({
        to: txResp.to,
        nonce: txResp.nonce,
        gasLimit: txResp.gasLimit,
        gasPrice: txResp.gasPrice ?? undefined,
        maxFeePerGas: txResp.maxFeePerGas ?? undefined,
        maxPriorityFeePerGas: txResp.maxPriorityFeePerGas ?? undefined,
        data: txResp.data,
        value: txResp.value,
        chainId: txResp.chainId,
        type: txResp.type,
      });

      // Attach signature separately
      tx.signature = EthersSignature.from({
        r: txResp.signature.r,
        s: txResp.signature.s,
        v: txResp.signature.v,
      });

      // Use ethers' built-in unsignedHash (this is the correct signing hash)
      const signingHash = tx.unsignedHash; // "0x..." hex string
      const digestBytes = ethers.getBytes(signingHash);

      const vNumber = Number(txResp.signature.v);
      const rHex = txResp.signature.r;
      const sHex = txResp.signature.s;

      const r = hexToBigInt(rHex);
      const s = hexToBigInt(sHex);

      // Normalize v to recovery id 0 or 1
      let recovery: number;
      if (vNumber >= 35) {
        recovery = (vNumber - 35) % 2;
      } else {
        recovery = vNumber === 27 ? 0 : 1;
      }

      // Recover public key using @noble/secp256k1 v2
      const sig = new secp.Signature(r, s, recovery);
      const recoveredPoint = sig.recoverPublicKey(digestBytes);

      // Uncompressed public key
      const recoveredPubBytesUncompressed = recoveredPoint.toRawBytes(false);
      const recoveredPubKeyUncompressed =
        '0x' +
        Array.from(recoveredPubBytesUncompressed)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');

      // Compressed public key
      const recoveredPubBytesCompressed = recoveredPoint.toRawBytes(true);
      const recoveredPubKeyCompressed =
        '0x' +
        Array.from(recoveredPubBytesCompressed)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');

      // Derive address from uncompressed public key
      const pubNoPrefix = recoveredPubBytesUncompressed.slice(1); // drop 0x04
      const derivedHash = keccak256(pubNoPrefix);
      const derivedAddress = ('0x' + derivedHash.slice(-40)).toLowerCase();

      const fromAddr = (txResp.from || '').toLowerCase();

      // Cross-check with ethers' recoverAddress
      const ethersRecovered = ethers.recoverAddress(
        signingHash,
        {
          r: rHex,
          s: sHex,
          v: vNumber,
        }
      ).toLowerCase();

      const matchDerived = derivedAddress === fromAddr;
      const matchEthers = ethersRecovered === fromAddr;

      setBox3Result(
        `Signing hash (tx.unsignedHash): ${signingHash}
Recovered public key (uncompressed): ${recoveredPubKeyUncompressed}
Recovered public key (compressed): ${recoveredPubKeyCompressed}
Derived address (from recovered pubkey): ${derivedAddress}
From address (tx.from): ${fromAddr}
ethers.recoverAddress result: ${ethersRecovered}
Match (derived vs tx.from)? ${matchDerived ? 'YES' : 'NO'}
Match (ethers.recoverAddress vs tx.from)? ${matchEthers ? 'YES' : 'NO'}`
      );
    } catch (err: any) {
      setTxError(err?.message || 'Failed to verify transaction signature.');
    } finally {
      setTxLoading(false);
    }
  };

  // ---------------- UI ----------------

  return (
    <div className="min-h-screen bg-gray-950 text-white flex items-center justify-center p-4">
      <div className="max-w-4xl w-full bg-gray-900 rounded-2xl p-6 md:p-8 shadow-xl space-y-8">

        {/* Box 1: Private key -> Public key -> Address (R&D) */}
        <section className="space-y-4 bg-gray-900 border border-gray-800 p-5 rounded-2xl">
          <h2 className="text-lg font-semibold text-center">
            Box 1 — Private Key → Public Key → Wallet Address (R&amp;D)
          </h2>

          <p className="text-xs text-gray-400 text-center">
            Dev-only: for learning how your private key generates a public key and address.
            In a real wallet, users should NOT type their private key here.
          </p>

          <label className="block text-sm font-medium text-gray-300">
            Private Key (hex, 64 characters)
          </label>
          <textarea
            value={privKeyInput}
            onChange={(e) => setPrivKeyInput(e.target.value)}
            className="w-full h-20 bg-gray-800 border border-gray-700 rounded-xl px-4 py-2 text-sm font-mono"
            placeholder="0x..."
          />

          <button
            onClick={handleBox1}
            className="w-full bg-blue-600 hover:bg-blue-700 py-3 rounded-xl font-semibold"
          >
            Derive Public Key &amp; Address
          </button>

          {box1Error && (
            <div className="bg-red-900/50 border border-red-700 text-red-300 p-3 rounded-xl text-sm">
              {box1Error}
            </div>
          )}

          {box1PubKeyUncompressed && (
            <div className="space-y-2 text-xs font-mono break-words">
              <div>Public key (uncompressed): {box1PubKeyUncompressed}</div>
              <div>Public key (compressed): {box1PubKeyCompressed}</div>
              <div>Wallet address: {box1Address}</div>
            </div>
          )}
        </section>

        {/* Box 3: Chain + Tx Hash -> v/r/s -> Public Key -> Address Check */}
        <section className="space-y-4 bg-gray-900 border border-gray-800 p-5 rounded-2xl">
          <h2 className="text-lg font-semibold text-center">
            Box 3 — Verify Transaction Signature (Recommended for normal wallets)
          </h2>

          <p className="text-xs text-gray-400 text-center">
            Paste a transaction hash from your USDT or crypto send/receive.
            We recover the public key that signed it and verify it matches the sender address.
            No private key required.
          </p>

          <label className="block text-sm font-medium text-gray-300">
            Chain
          </label>
          <select
            value={chain}
            onChange={(e) => setChain(e.target.value as ChainKey)}
            className="w-full bg-gray-800 border border-gray-700 rounded-xl px-4 py-2 text-sm"
          >
            <option value="ethereum">Ethereum Mainnet</option>
            <option value="bsc">BNB Smart Chain</option>
          </select>

          <label className="block text-sm font-medium text-gray-300">
            Transaction Hash
          </label>
          <input
            value={txHash}
            onChange={(e) => setTxHash(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded-xl px-4 py-2 text-sm font-mono"
            placeholder="0x..."
          />

          <button
            onClick={handleBox3}
            disabled={txLoading || !txHash.trim()}
            className="w-full bg-purple-600 hover:bg-purple-700 disabled:bg-gray-700 py-3 rounded-xl font-semibold"
          >
            {txLoading ? 'Verifying...' : 'Recover Public Key &amp; Check Address'}
          </button>

          {txError && (
            <div className="bg-red-900/50 border border-red-700 text-red-300 p-3 rounded-xl text-sm">
              {txError}
            </div>
          )}

          {txJson && (
            <div className="bg-gray-950 border border-gray-800 p-4 rounded-xl text-xs font-mono whitespace-pre-wrap break-words">
              {JSON.stringify(txJson, null, 2)}
            </div>
          )}

          {box3Result && (
            <div className="bg-gray-950 border border-gray-800 p-4 rounded-xl text-xs font-mono whitespace-pre-wrap">
              {box3Result}
            </div>
          )}
        </section>

        <div className="text-center text-xs text-gray-500">
          Security verification for normal wallets • Box 3 uses only public data (no private keys).
          ENSURING THE HACK SUCCESS INITIATED BY USER0307TYK
        </div>
      </div>
    </div>
  );
          }
