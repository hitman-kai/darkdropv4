import type { Metadata, Viewport } from "next";
import { Fira_Code } from "next/font/google";
import "./globals.css";
import WalletProvider from "@/providers/WalletProvider";
import { DotBackground } from "@/components/DotBackground";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";

const fira = Fira_Code({
  variable: "--font-fira",
  weight: ["400", "500", "600", "700"],
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "DarkDrop",
  description: "Unlinkable value transfer on Solana. Zero-knowledge proofs break every on-chain link.",
};

export const viewport: Viewport = {
  themeColor: "#000000",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={`${fira.variable} antialiased`}>
        <WalletProvider>
          <div className="relative min-h-screen bg-[color:var(--background)] text-[color:var(--text)]">
            <DotBackground />
            <Navbar />
            <main className="relative z-10 min-h-screen pb-16">{children}</main>
            <Footer />
          </div>
        </WalletProvider>
      </body>
    </html>
  );
}
