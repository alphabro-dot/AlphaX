'use client';

import { useState } from 'react';
import * as secp from '@noble/secp256k1';
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';

export default function Home() {
  const [privateKey, setPrivateKey] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [evmAddress, setEvmAddress] = useState('');
  const [fullHash, setFullHash] = useState('');
  const [showProcess, setShowProcess] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const convertKey = async () => {
    setLoading(true);
    setError('');
    setPublicKey('');
    setEvmAddress('');
    setFullHash('');
    setShowProcess(false);

    try {
      let cleanKey = privateKey.trim().replace(/^0x/i, '');
      
      if (!/^[0-9a-fA-F]{64}$/.test(cleanKey)) {
        throw new Error('Private key must be exactly 64 hex characters (32 bytes)');
      }

      const privBytes = secp.utils.hexToBytes(cleanKey);
      
      // Public Key
      const pubCompressed = secp.getPublicKey(privBytes, true);
      const pubHex = secp.utils.bytesToHex(pubCompressed);
      
      // For Address
      const pubUncompressed = secp.getPublicKey(privBytes, false);
      const pubWithoutPrefix = pubUncompressed.slice(1);
      
      const hashBytes = keccak256(pubWithoutPrefix);
      const hashHex = secp.utils.bytesToHex(hashBytes);
      const address = '0x' + secp.utils.bytesToHex(hashBytes.slice(-20));

      setPublicKey('0x' + pubHex);
      setEvmAddress(address);
      setFullHash(hashHex);
    } catch (err: any) {
      setError(err.message || 'Invalid private key');
    } finally {
      setLoading(false);
    }
  };

  const toggleProcess = () => setShowProcess(!showProcess);

  return (
    <div className="min-h-screen bg-gray-950 text-white flex items-center justify-center p-4">
      <div className="max-w-2xl w-full bg-gray-900 rounded-2xl p-8 shadow-xl">
        <h1 className="text-3xl font-bold mb-2 text-center">secp256k1 → EVM Address</h1>
        <p className="text-gray-400 text-center mb-8">Private Key → Public Key → Address (with full process)</p>

        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium mb-2 text-gray-300">
              Private Key (hex)
            </label>
            <textarea
              value={privateKey}
              onChange={(e) => setPrivateKey(e.target.value)}
              placeholder="Enter 64 hex characters..."
              className="w-full h-24 bg-gray-800 border border-gray-700 rounded-xl px-4 py-3 text-sm font-mono focus:outline-none focus:border-blue-500 resize-y"
            />
          </div>

          <div className="flex gap-4">
            <button
              onClick={convertKey}
              disabled={loading || !privateKey.trim()}
              className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 py-4 rounded-xl font-semibold transition"
            >
              {loading ? 'Processing...' : 'Convert'}
            </button>
            
            <button
              onClick={toggleProcess}
              disabled={!publicKey}
              className="flex-1 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-800 py-4 rounded-xl font-semibold transition"
            >
              {showProcess ? 'Hide Process' : 'Show Forward + Backward Process'}
            </button>
          </div>

          {error && (
            <div className="bg-red-950 border border-red-800 text-red-400 p-4 rounded-xl text-sm">
              {error}
            </div>
          )}

          {publicKey && (
            <div className="bg-emerald-950 border border-emerald-800 p-5 rounded-xl">
              <div className="text-emerald-400 font-medium mb-4">Final Results</div>
              <div className="font-mono text-sm space-y-3">
                <div><span className="text-gray-400">Public Key:</span> {publicKey}</div>
                <div><span className="text-gray-400">EVM Address:</span> {evmAddress}</div>
              </div>
            </div>
          )}

          {showProcess && publicKey && (
            <div className="bg-gray-800 border border-gray-700 p-6 rounded-xl text-sm overflow-auto max-h-[70vh]">
              <h3 className="font-semibold mb-6 text-lg border-b border-gray-600 pb-4">🔄 Full Cryptographic Process</h3>
              
              {/* Forward */}
              <div className="mb-10">
                <div className="text-green-400 mb-4 font-medium flex items-center gap-2">
                  → FORWARD: Private Key to Address
                </div>
                <div className="space-y-6 pl-6 border-l-2 border-green-600">
                  <div>
                    <div className="text-gray-400">1. Private Key (input)</div>
                    <div className="font-mono break-all mt-1">{privateKey}</div>
                  </div>
                  <div className="text-2xl text-gray-600">↓</div>
                  <div>
                    <div className="text-gray-400">2. Public Key (compressed) — secp256k1 curve point multiplication</div>
                    <div className="font-mono break-all mt-1">{publicKey}</div>
                  </div>
                  <div className="text-2xl text-gray-600">↓</div>
                  <div>
                    <div className="text-gray-400">3. Keccak-256 Hash of Public Key (without 0x04 prefix)</div>
                    <div className="font-mono break-all mt-1 text-amber-300">{fullHash}</div>
                  </div>
                  <div className="text-2xl text-gray-600">↓</div>
                  <div>
                    <div className="text-gray-400">4. EVM Address — last 20 bytes of the hash</div>
                    <div className="font-mono break-all mt-1 text-xl text-white">{evmAddress}</div>
                  </div>
                </div>
              </div>

              {/* Backward */}
              <div>
                <div className="text-amber-400 mb-4 font-medium flex items-center gap-2">
                  ← BACKWARD: Address back to Private Key
                </div>
                <div className="space-y-6 pl-6 border-l-2 border-amber-600">
                  <div>
                    <div className="text-gray-400">1. EVM Address</div>
                    <div className="font-mono break-all mt-1">{evmAddress}</div>
                  </div>
                  <div className="text-2xl text-gray-600">↑</div>
                  <div>
                    <div className="text-gray-400">2. Part of Keccak-256 Hash</div>
                    <div className="font-mono break-all mt-1 text-amber-300">{fullHash}</div>
                  </div>
                  <div className="text-2xl text-gray-600">↑</div>
                  <div>
                    <div className="text-gray-400">3. Public Key — (secp256k1 point)</div>
                    <div className="font-mono break-all mt-1">{publicKey}</div>
                  </div>
                  <div className="text-2xl text-gray-600">↑</div>
                  <div>
                    <div className="text-gray-400">4. Private Key — (mathematically hard to reverse in practice)</div>
                    <div className="font-mono break-all mt-1">{privateKey}</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
