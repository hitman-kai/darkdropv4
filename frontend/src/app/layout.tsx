import type { Metadata, Viewport } from "next";
import { Fira_Code } from "next/font/google";
import "./globals.css";
import WalletProvider from "@/providers/WalletProvider";
import { DotBackground } from "@/components/DotBackground";
import RetroScrollbar from "@/components/RetroScrollbar";
import SnakeBackground from "@/components/SnakeBackground";
import ClaimBackground from "@/components/ClaimBackground";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";


const fira = Fira_Code({
  variable: "--font-fira",
  weight: ["400", "500", "600", "700"],
  subsets: ["latin"],
  display: "swap",
});

const SITE_URL = "https://darkdrop.app";
const SITE_TITLE = "DarkDrop";
const SITE_DESCRIPTION =
  "Unlinkable value transfer on Solana. Zero-knowledge proofs break every on-chain link.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: SITE_TITLE,
  description: SITE_DESCRIPTION,
  openGraph: {
    title: SITE_TITLE,
    description: SITE_DESCRIPTION,
    url: SITE_URL,
    siteName: SITE_TITLE,
    images: [{ url: "/opengraph-image", width: 1200, height: 630, alt: SITE_TITLE }],
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: SITE_TITLE,
    description: SITE_DESCRIPTION,
    images: ["/opengraph-image"],
    creator: "@darkdrop_sol",
  },
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
            <SnakeBackground />
            <ClaimBackground />
            <RetroScrollbar />
            <Navbar />
            <main className="relative z-10 min-h-screen pb-16">{children}</main>
            <Footer />
          </div>
        </WalletProvider>
      </body>
    </html>
  );
}
