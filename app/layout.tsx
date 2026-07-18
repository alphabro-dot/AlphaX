import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'secp256k1 → EVM Address Tool',
  description: 'Convert Private Key to Public Key and EVM Wallet Address with step-by-step process',
  icons: {
    icon: '/favicon.ico',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="bg-gray-950 text-white">
        {children}
      </body>
    </html>
  )
}
