'use client';

import { useState } from 'react';
import * as secp from '@noble/secp256k1';
import { keccak256 } from 'js-sha3';
import { ethers } from 'ethers';

type TxInfo = {
  hash: string;
  from: string;
  to: string | null;
  nonce: number;
  gasLimit: string;
  gasPrice: string | null;
  maxFeePerGas: string | null;
  maxPriorityFeePerGas: string | null;
  value: string;
  data: string;
  chainId: string;
  type: string;
  signatureV: string;
  signatureR: string;
  signatureS: string;
  unsignedTx: string;
  txHashComputed: string;
  methodId: string;
  decodedTo: string | null;
  decodedValue: string | null;
};

export default function Home() {
  const [privateKey, setPrivateKey] = useState('');
  const [compressedPubKey, setCompressedPubKey] = useState('');
  const [uncompressedPubKey, setUncompressedPubKey] = useState('');
  const [walletAddress, setWalletAddress] = useState('');
  const [calcDetails, setCalcDetails] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const [verifyAddress, setVerifyAddress] = useState('');
  const [verifyMessage, setVerifyMessage] = useState('');
  const [verifySignature, setVerifySignature] = useState('');
  const [verifyResult, setVerifyResult] = useState('');

  const [txHash, setTxHash] = useState('');
  const [txLoading, setTxLoading] = useState(false);
  const [txError, setTxError] = useState('');
  const [txInfo, setTxInfo] = useState<TxInfo | null>(null);

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
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');

      const uncompressedHex =
        '0x' +
        Array.from(pubUncompressed)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');

      const xHex = Array.from(pubUncompressed.slice(1, 33))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      const yHex = Array.from(pubUncompressed.slice(33))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      const hashHex = keccak256(pubUncompressed.slice(1));
      const address = '0x' + hashHex.slice(-40);

      setCompressedPubKey(compressedHex);
      setUncompressedPubKey(uncompressedHex);
      setWalletAddress(address);

      setCalcDetails(
        `1) Private key input
   Hex: 0x${cleanKey}
   Bytes: 32
   Bits: 256

2) Convert private key to secp256k1 public key
   Operation: P = d × G
   Result = public key point (X, Y)

3) Public key (compressed)
   Value: ${compressedHex}

4) Public key (uncompressed)
   Value: ${uncompressedHex}

5) Split uncompressed public key
   X: 0x${xHex}
   Y: 0x${yHex}

6) Ethereum / EVM address derivation
   Keccak-256(X || Y): ${hashHex}
   Address: ${address}`
      );
    } catch (err: any) {
      setError(err?.message || 'Failed to generate keys');
    } finally {
      setLoading(false);
    }
  };

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

      const digest = ethers.hashMessage(msgInput);
      const digestBytes = ethers.getBytes(digest);
      const recoveredPubKey = ethers.SigningKey.recoverPublicKey(digestBytes, sigInput);
      const recoveredAddress = ethers.computeAddress(recoveredPubKey).toLowerCase();

      const pubHex = recoveredPubKey.startsWith('0x') ? recoveredPubKey.slice(2) : recoveredPubKey;
      const pubHexNoPrefix = pubHex.startsWith('04') ? pubHex.slice(2) : pubHex;
      const derivedHash = keccak256(ethers.getBytes('0x' + pubHexNoPrefix));
      const derivedAddress = ('0x' + derivedHash.slice(-40)).toLowerCase();

      const expectedAddress = addrInput.toLowerCase();
      const matchRecovered = recoveredAddress === expectedAddress;
      const matchDerived = derivedAddress === expectedAddress;

      const result =
        `1) Inputs
   Wallet address: ${addrInput}
   Message: "${msgInput}"
   Signature: ${sigInput}

2) Hash the message (Ethereum style)
   digest: ${digest}

3) ECDSA public key recovery
   Recovered public key: ${recoveredPubKey}
   Recovered address from signature: ${recoveredAddress}

4) Derive address from recovered public key
   Keccak-256(X || Y): ${derivedHash}
   Derived address: ${derivedAddress}

5) Compare with input address
   Expected address: ${expectedAddress}
   Match recoveredAddress? ${matchRecovered ? 'YES' : 'NO'}
   Match derivedAddress? ${matchDerived ? 'YES' : 'NO'}

Result: ${matchRecovered && matchDerived ? '✅ The recovered public key corresponds to the given wallet address.' : '❌ The signature does NOT belong to the given wallet address.'}`;

      setVerifyResult(result);
    } catch (err: any) {
      setVerifyResult(`Verification failed: ${err?.message || String(err)}`);
    }
  };

  const fetchTxDetails = async () => {
    setTxLoading(true);
    setTxError('');
    setTxInfo(null);

    try {
      const cleanHash = txHash.trim();
      if (!/^0x[a-fA-F0-9]{64}$/.test(cleanHash)) {
        throw new Error('Transaction hash must be a 66-character hex string starting with 0x');
      }

      if (typeof window === 'undefined' || !(window as any).ethereum) {
        throw new Error('No injected wallet provider found. Open this page in a wallet-enabled browser.');
      }

      const provider = new ethers.JsonRpcProvider('https://ethereum.publicnode.com');
const tx = await provider.getTransaction(cleanHash);

      if (!tx) {
        throw new Error('Transaction not found on the connected network');
      }

      const sig = tx.signature;
      const gasPrice = tx.gasPrice ? tx.gasPrice.toString() : null;
      const maxFeePerGas = tx.maxFeePerGas ? tx.maxFeePerGas.toString() : null;
      const maxPriorityFeePerGas = tx.maxPriorityFeePerGas ? tx.maxPriorityFeePerGas.toString() : null;

      let unsignedTx = '';
      let txHashComputed = '';

      try {
        const unsigned = ethers.Transaction.from({
          type: tx.type,
          to: tx.to,
          nonce: tx.nonce,
          gasLimit: tx.gasLimit,
          gasPrice: tx.gasPrice ?? undefined,
          maxFeePerGas: tx.maxFeePerGas ?? undefined,
          maxPriorityFeePerGas: tx.maxPriorityFeePerGas ?? undefined,
          value: tx.value,
          data: tx.data,
          chainId: tx.chainId
        });

        unsignedTx = unsigned.unsignedSerialized;
        txHashComputed = ethers.keccak256(unsignedTx);
      } catch {
        unsignedTx = 'Unable to reconstruct unsigned transaction with current tx type';
        txHashComputed = 'Unable to compute';
      }

      const input = tx.data || '';
      const methodId = input.length >= 10 ? input.slice(0, 10) : '0x';

      let decodedTo: string | null = null;
      let decodedValue: string | null = null;

      if (methodId.toLowerCase() === '0xa9059cbb' && input.length >= 138) {
        decodedTo = '0x' + input.slice(34, 74);
        decodedValue = BigInt('0x' + input.slice(74, 138)).toString();
      }

      setTxInfo({
        hash: tx.hash,
        from: tx.from || '',
        to: tx.to,
        nonce: tx.nonce,
        gasLimit: tx.gasLimit.toString(),
        gasPrice,
        maxFeePerGas,
        maxPriorityFeePerGas,
        value: tx.value.toString(),
        data: tx.data,
        chainId: tx.chainId.toString(),
        type: String(tx.type),
        signatureV: sig?.v != null ? String(sig.v) : '',
        signatureR: sig?.r || '',
        signatureS: sig?.s || '',
        unsignedTx,
        txHashComputed,
        methodId,
        decodedTo,
        decodedValue
      });
    } catch (err: any) {
      setTxError(err?.message || 'Failed to fetch transaction');
    } finally {
      setTxLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-white flex items-center justify-center p-4">
      <div className="max-w-4xl w-full bg-gray-900 rounded-2xl p-6 md:p-8 shadow-xl space-y-8">
        <h1 className="text-3xl font-bold text-center">secp256k1 Key Tool</h1>
        <p className="text-gray-400 text-center">
          Private key derivation, signed-message recovery, and transaction inspection
        </p>

        <section className="space-y-5 bg-gray-900 border border-gray-800 p-5 rounded-2xl">
          <h2 className="text-lg font-semibold text-center">
            Box 1 — Private Key → Public Key → Address
          </h2>

          <label className="block text-sm font-medium text-gray-300">
            Private Key (hex)
          </label>
          <textarea
            value={privateKey}
            onChange={(e) => setPrivateKey(e.target.value)}
            placeholder="Enter 64 hex characters"
            className="w-full h-24 bg-gray-800 border border-gray-700 rounded-xl px-4 py-3 text-sm font-mono focus:outline-none focus:border-blue-500 resize-y"
          />

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
                <div className="text-emerald-400 text-sm mb-2">Compressed Public Key</div>
                <div className="font-mono break-all text-emerald-100 text-sm">{compressedPubKey}</div>
              </div>
              <div className="bg-emerald-950 border border-emerald-800 p-5 rounded-xl">
                <div className="text-emerald-400 text-sm mb-2">Wallet Address</div>
                <div className="font-mono break-all text-emerald-100 text-sm">{walletAddress}</div>
              </div>
            </div>
          )}

          {uncompressedPubKey && (
            <div className="bg-indigo-950 border border-indigo-800 p-5 rounded-xl">
              <div className="text-indigo-400 text-sm mb-2">Uncompressed Public Key</div>
              <div className="font-mono break-all text-indigo-100 text-sm">{uncompressedPubKey}</div>
            </div>
          )}

          {calcDetails && (
            <div className="bg-gray-950 border border-gray-800 p-5 rounded-xl">
              <div className="text-sm font-semibold mb-3 text-gray-300">Calculation Steps</div>
              <pre className="text-xs text-gray-200 font-mono whitespace-pre-wrap break-words leading-relaxed">
                {calcDetails}
              </pre>
            </div>
          )}
        </section>

        <section className="space-y-5 bg-gray-900 border border-gray-800 p-5 rounded-2xl">
          <h2 className="text-lg font-semibold text-center">
            Box 2 — Wallet Address + Message + Signature → Public Key → Address Check
          </h2>

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
            <div className="bg-gray-950 border border-gray-800 p-4 rounded-xl">
              <div className="text-sm font-semibold mb-2 text-gray-300">Verification Result</div>
              <pre className="text-xs text-gray-200 font-mono whitespace-pre-wrap break-words leading-relaxed">
                {verifyResult}
              </pre>
            </div>
          )}
        </section>

        <section className="space-y-5 bg-gray-900 border border-gray-800 p-5 rounded-2xl">
          <h2 className="text-lg font-semibold text-center">
            Box 3 — Transaction Hash → Fields, v/r/s, and Input Decode
          </h2>

          <label className="block text-sm font-medium text-gray-300">
            Transaction Hash
          </label>
          <input
            value={txHash}
            onChange={(e) => setTxHash(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded-xl px-4 py-2 text-sm font-mono focus:outline-none focus:border-blue-500"
            placeholder="0x..."
          />

          <button
            onClick={fetchTxDetails}
            disabled={txLoading || !txHash.trim()}
            className="w-full bg-purple-600 hover:bg-purple-700 disabled:bg-gray-700 py-3 rounded-xl font-semibold transition disabled:cursor-not-allowed"
          >
            {txLoading ? 'Fetching...' : 'Fetch Transaction Data'}
          </button>

          {txError && (
            <div className="bg-red-900/50 border border-red-700 text-red-300 p-4 rounded-xl text-sm">
              {txError}
            </div>
          )}

          {txInfo && (
            <div className="bg-gray-950 border border-gray-800 p-4 rounded-xl">
              <pre className="text-xs text-gray-200 font-mono whitespace-pre-wrap break-words leading-relaxed">
                {JSON.stringify(txInfo, null, 2)}
              </pre>
            </div>
          )}
        </section>

        <div className="text-center text-xs text-gray-500">
          Runs 100% in your browser • No data leaves your device
        </div>
      </div>
    </div>
  );
}
