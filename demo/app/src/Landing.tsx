import { useNavigate } from "react-router-dom";

export default function Landing() {
  const nav = useNavigate();

  return (
    <div style={s.page}>
      <div style={s.hero}>
        <div style={s.badge}>devnet</div>
        <h1 style={s.title}>solana-mpp</h1>
        <p style={s.tagline}>HTTP payments for APIs, powered by Solana</p>

        <div style={s.flow}>
          <span style={s.flowStep}>{"\u2192"} Request</span>
          <span style={{ ...s.flowStep, color: "#9945FF" }}>
            {"\u25ce"} 402
          </span>
          <span style={{ ...s.flowStep, color: "#14F195" }}>
            {"\u25c8"} Pay
          </span>
          <span style={{ ...s.flowStep, color: "#FFD700" }}>
            {"\u2713"} Access
          </span>
        </div>

        <pre style={s.codePreview}>{`// Server: charge 0.001 SOL per request
const mppx = Mppx.create({
  methods: [solana.charge({ recipient, network: 'devnet' })],
})
const result = await mppx.charge({ amount: '1000000' })(request)

// Client: pay transparently
const mppx = Mppx.create({
  methods: [solana.charge({ signer })],
})
const response = await mppx.fetch(url)`}</pre>

        <div style={s.links}>
          <a
            style={s.link}
            href="https://mpp.dev"
            target="_blank"
            rel="noopener"
          >
            mpp.dev
          </a>
          <span style={s.dot}>{"\u00b7"}</span>
          <a
            style={s.link}
            href="https://github.com/solana-foundation/pay-kit"
            target="_blank"
            rel="noopener"
          >
            GitHub
          </a>
        </div>

        <div style={s.ctaRow}>
          <button style={s.cta} onClick={() => nav("/charges")}>
            Try Charge Demo
          </button>
        </div>
      </div>
    </div>
  );
}

const s: Record<string, React.CSSProperties> = {
  page: {
    minHeight: "100vh",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: 20,
    background: "radial-gradient(ellipse at center, #0f0f1a 0%, #0A0A0A 70%)",
  },
  hero: {
    textAlign: "center",
    maxWidth: 560,
  },
  badge: {
    display: "inline-block",
    padding: "4px 12px",
    background: "#14F19522",
    border: "1px solid #14F19544",
    borderRadius: 20,
    fontSize: 11,
    color: "#14F195",
    marginBottom: 20,
    letterSpacing: 1,
  },
  title: {
    fontSize: 48,
    fontWeight: 700,
    color: "#fff",
    margin: 0,
    letterSpacing: -1,
  },
  tagline: {
    fontSize: 16,
    color: "#888",
    marginTop: 8,
  },
  flow: {
    display: "flex",
    justifyContent: "center",
    gap: 24,
    marginTop: 32,
    marginBottom: 32,
  },
  flowStep: {
    fontSize: 14,
    color: "#E0E0E0",
  },
  codePreview: {
    textAlign: "left",
    background: "#111",
    border: "1px solid #222",
    borderRadius: 12,
    padding: 20,
    fontSize: 12,
    lineHeight: 1.7,
    color: "#ccc",
    overflow: "auto",
    margin: "0 auto",
  },
  links: {
    marginTop: 24,
    fontSize: 13,
    color: "#666",
  },
  link: {
    color: "#9945FF",
    textDecoration: "none",
  },
  dot: {
    margin: "0 8px",
    color: "#333",
  },
  ctaRow: {
    marginTop: 24,
    display: "flex",
    justifyContent: "center",
    gap: 10,
    flexWrap: "wrap",
  },
  cta: {
    padding: "14px 32px",
    background: "#9945FF",
    border: "none",
    borderRadius: 10,
    color: "#fff",
    fontFamily: "JetBrains Mono, monospace",
    fontSize: 14,
    fontWeight: 600,
    cursor: "pointer",
    letterSpacing: 0.5,
  },
};
