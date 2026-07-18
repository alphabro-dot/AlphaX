'use client';

import { useState } from 'react';
import * as secp from '@noble/secp256k1';
import { keccak256 } from 'js-sha3';

export default function Home() {
  const [privateKey, setPrivateKey] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [address, setAddress] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const convertKey = async () => {
    setLoading(true);
    setError('');
    setPublicKey('');
    setAddress('');

    try {
      // Clean and validate private key
      let cleanKey = privateKey.trim().replace(/^0x/i, '').toLowerCase();

      if (!/^[0-9a-f]{64}$/.test(cleanKey)) {
        throw new Error('Private key must be exactly 64 hexadecimal characters (32 bytes)');
      }

      // Convert hex string to Uint8Array (32 bytes)
      const privBytes = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        privBytes[i] = parseInt(cleanKey.substr(i * 2, 2), 16);
      }

      // 1) Compressed public key (33 bytes)
      const pubCompressed = secp.getPublicKey(privBytes, true);

      // 2) Uncompressed public key (65 bytes: 04 || X || Y)
      const pubUncompressed = secp.getPublicKey(privBytes, false);

      // 3) Drop leading 0x04 to get X||Y (64 bytes)
      const pubXY = pubUncompressed.slice(1);

      // 4) Keccak-256 hash of X||Y (Ethereum-style)
      // js-sha3 keccak256 accepts Uint8Array directly and returns hex string
      const hashHex = keccak256(pubXY);

      // 5) Last 20 bytes (40 hex chars) are the EVM address
      const addr = '0x' + hashHex.slice(-40);

      // Convert compressed public key bytes to hex
      const pubHex = Array.from(pubCompressed)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');

      setPublicKey('0x' + pubHex);
      setAddress(addr);
    } catch (err: any) {
      setError(err.message || 'Failed to generate keys');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-white flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-gray-900 rounded-2xl p-8 shadow-xl">
        <h1 className="text-3xl font-bold mb-2 text-center">secp256k1 Key Tool</h1>
        <p className="text-gray-400 text-center mb-8">
          Private Key → Public Key → EVM Address
        </p>

        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium mb-2 text-gray-300">
              Private Key (hex)
            </label>
            <textarea
              value={privateKey}
              onChange={(e) => setPrivateKey(e.target.value)}
              placeholder="Enter 64 hex characters (e.g. 0000000000000000000000000000000000000000000000000000000000000001)"
              className="w-full h-28 bg-gray-800 border border-gray-700 rounded-xl px-4 py-3 text-sm font-mono focus:outline-none focus:border-blue-500 resize-y"
            />
          </div>

          <button
            onClick={convertKey}
            disabled={loading || !privateKey.trim()}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 py-4 rounded-xl font-semibold transition disabled:cursor-not-allowed"
          >
            {loading ? 'Generating...' : 'Generate Keys'}
          </button>

          {error && (
            <div className="bg-red-900/50 border border-red-700 text-red-300 p-4 rounded-xl text-sm">
              {error}
            </div>
          )}

          {publicKey && (
            <div className="bg-emerald-950 border border-emerald-800 p-5 rounded-xl space-y-4">
              <div>
                <div className="text-emerald-400 text-sm mb-2">
                  Public Key (Compressed)
                </div>
                <div className="font-mono break-all text-emerald-100 text-sm leading-relaxed">
                  {publicKey}
                </div>
                <button
                  onClick={() => navigator.clipboard.writeText(publicKey)}
                  className="mt-3 text-xs bg-emerald-900 hover:bg-emerald-800 px-4 py-2 rounded-lg transition"
                >
                  📋 Copy Public Key
                </button>
              </div>

              {address && (
                <div className="border-t border-emerald-800 pt-4">
                  <div className="text-emerald-400 text-sm mb-2">
                    EVM Address (Ethereum-style)
                  </div>
                  <div className="font-mono break-all text-emerald-100 text-sm leading-relaxed">
                    {address}
                  </div>
                  <button
                    onClick={() => navigator.clipboard.writeText(address)}
                    className="mt-3 text-xs bg-emerald-900 hover:bg-emerald-800 px-4 py-2 rounded-lg transition"
                  >
                    📋 Copy Address
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="mt-8 text-center text-xs text-gray-500">
          Runs 100% in your browser • No data leaves your device
        </div>
      </div>
    </div>
  );
}
