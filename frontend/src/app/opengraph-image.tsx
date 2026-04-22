import { ImageResponse } from "next/og";

export const runtime = "edge";
export const alt = "DarkDrop — Zero-knowledge dead drops on Solana";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default async function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          background: "#000000",
          backgroundImage:
            "radial-gradient(circle at 50% 50%, rgba(0,255,65,0.08) 0%, transparent 60%), linear-gradient(rgba(0,255,65,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,65,0.05) 1px, transparent 1px)",
          backgroundSize: "100% 100%, 40px 40px, 40px 40px",
          padding: "72px 88px",
          fontFamily: "monospace",
          color: "#e0e0e0",
          position: "relative",
        }}
      >
        <div
          style={{
            display: "flex",
            position: "absolute",
            left: 88,
            top: 72,
            bottom: 72,
            width: 2,
            background:
              "linear-gradient(to bottom, transparent, rgba(0,255,65,0.4), transparent)",
          }}
        />

        <div
          style={{
            display: "flex",
            fontSize: 20,
            letterSpacing: "0.35em",
            color: "rgba(0,255,65,0.5)",
            marginLeft: 32,
            marginBottom: 48,
          }}
        >
          OUTPUT // 0X00 — UNLINKABLE SOLANA TRANSFERS
        </div>

        <div
          style={{
            display: "flex",
            flexDirection: "column",
            fontSize: 112,
            fontWeight: 300,
            lineHeight: 1.05,
            letterSpacing: "-0.02em",
            marginLeft: 32,
          }}
        >
          <div style={{ display: "flex" }}>Zero-knowledge</div>
          <div style={{ display: "flex", color: "#00ff41" }}>dead drops.</div>
        </div>

        <div
          style={{
            display: "flex",
            fontSize: 28,
            color: "rgba(224,224,224,0.5)",
            marginLeft: 32,
            marginTop: 40,
          }}
        >
          No decoded amounts. No inner instructions. No link.
        </div>

        <div
          style={{
            position: "absolute",
            bottom: 72,
            right: 88,
            display: "flex",
            alignItems: "center",
            gap: 16,
            fontSize: 20,
            letterSpacing: "0.2em",
            color: "rgba(0,255,65,0.6)",
          }}
        >
          <div
            style={{
              display: "flex",
              width: 10,
              height: 10,
              borderRadius: 10,
              background: "#00ff41",
              boxShadow: "0 0 12px #00ff41",
            }}
          />
          <div style={{ display: "flex" }}>DARKDROP · V4 DEVNET</div>
        </div>
      </div>
    ),
    size,
  );
}
