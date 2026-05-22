"use client";

import { useState } from "react";
import { Shield, CheckCircle, XCircle, Loader2, ExternalLink, Copy, ChevronDown, ChevronUp } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8765";

type ProofStatus = "PROVED" | "NOT_PROVED" | "ERROR";

interface DerivationStep {
  step: number;
  axiom: string;
  tx_hash: string;
  from_addr: string;
  to_addr: string;
  description: string;
}

interface Certificate {
  certificate_id: string;
  entity: string;
  proof_status: ProofStatus;
  z3_result: string;
  axioms_applied: string[];
  hop_count: number;
  solver_time_ms: number;
  derivation_steps: DerivationStep[];
  sha256: string;
  signature: string;
  pubkey_fp: string;
  signing_scheme: string;
  timestamp: string;
  issuer: string;
  claim_seed: string;
  claim_target: string;
}

interface ProveResponse {
  certificate: Certificate;
  comparison: {
    chainalysis_reactor: Record<string, unknown>;
    verdict_engine: Record<string, unknown>;
  };
}

const AXIOM_LABELS: Record<string, string> = {
  CIO:  "Common-Input Ownership",
  CAD:  "Change Address Detection",
  PEEL: "Peeling Chain",
  XFR:  "Exchange Fan-In",
};

export default function Home() {
  const [graph, setGraph] = useState("lazarus_bybit_2025");
  const [scheme, setScheme] = useState<"Ed25519" | "ML-DSA-65">("Ed25519");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ProveResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showChain, setShowChain] = useState(true);
  const [showRaw, setShowRaw] = useState(false);
  const [copied, setCopied] = useState(false);

  async function runProof() {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch(`${API}/prove`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ graph, scheme }),
      });
      if (!res.ok) {
        const d = await res.json();
        throw new Error(d.detail || `HTTP ${res.status}`);
      }
      setResult(await res.json());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  function copy(text: string) {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  const cert = result?.certificate;
  const proved = cert?.proof_status === "PROVED";

  return (
    <main className="min-h-screen bg-[#0a0a0f] text-gray-100 font-mono">
      {/* Header */}
      <header className="border-b border-gray-800 px-8 py-5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-cyan-400" />
          <span className="text-lg font-bold tracking-tight text-white">VERDICT ENGINE</span>
          <span className="text-xs text-gray-500 border border-gray-700 rounded px-2 py-0.5">v1.0.0</span>
        </div>
        <span className="text-xs text-gray-500">EVIDENTUM — Proof Intelligence</span>
      </header>

      <div className="max-w-5xl mx-auto px-8 py-10 space-y-8">

        {/* Hero */}
        <div className="space-y-2">
          <h1 className="text-2xl font-bold text-white leading-tight">
            Formally Verified Blockchain Attribution
          </h1>
          <p className="text-gray-400 text-sm max-w-2xl">
            Attribution claims are{" "}
            <span className="text-cyan-400 font-semibold">proven via Z3 SMT solver</span>
            , not asserted. Certificates are Ed25519 / ML-DSA-65 signed and
            machine-verifiable by any third party. No black boxes.
          </p>
        </div>

        {/* Proof panel */}
        <div className="border border-gray-800 rounded-lg p-6 space-y-5 bg-[#0d0d14]">
          <div className="text-xs text-gray-500 uppercase tracking-widest">Run Proof</div>

          <div className="flex flex-wrap gap-4 items-end">
            <div className="space-y-1">
              <label className="text-xs text-gray-500">Transaction Graph</label>
              <select
                value={graph}
                onChange={e => setGraph(e.target.value)}
                className="bg-[#111118] border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-cyan-500 outline-none"
              >
                <option value="lazarus_bybit_2025">Lazarus APT38 — Bybit $1.46B (2025)</option>
                <option value="ruja_oncoin">Ruja Ignatova — OneCoin Scheme</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="text-xs text-gray-500">Signing Scheme</label>
              <select
                value={scheme}
                onChange={e => setScheme(e.target.value as "Ed25519" | "ML-DSA-65")}
                className="bg-[#111118] border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-cyan-500 outline-none"
              >
                <option value="Ed25519">Ed25519 (classical)</option>
                <option value="ML-DSA-65">ML-DSA-65 — FIPS 204 (post-quantum)</option>
              </select>
            </div>

            <button
              onClick={runProof}
              disabled={loading}
              className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white px-5 py-2 rounded text-sm font-semibold transition-colors"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
              {loading ? "Proving…" : "Run Z3 Proof"}
            </button>
          </div>

          {error && (
            <div className="border border-red-800 bg-red-950/30 rounded p-3 text-sm text-red-400">
              {error}
            </div>
          )}
        </div>

        {/* Certificate */}
        {cert && (
          <div className="space-y-5">

            {/* Status banner */}
            <div className={`border rounded-lg p-5 flex items-start gap-4 ${
              proved
                ? "border-green-700 bg-green-950/20"
                : "border-red-700 bg-red-950/20"
            }`}>
              {proved
                ? <CheckCircle className="w-6 h-6 text-green-400 mt-0.5 shrink-0" />
                : <XCircle    className="w-6 h-6 text-red-400 mt-0.5 shrink-0" />}
              <div className="space-y-1 flex-1">
                <div className="flex items-center gap-3 flex-wrap">
                  <span className={`text-lg font-bold ${proved ? "text-green-400" : "text-red-400"}`}>
                    {cert.proof_status}
                  </span>
                  <span className="text-xs text-gray-500 border border-gray-700 rounded px-2 py-0.5">
                    Z3 {cert.z3_result.toUpperCase()}
                  </span>
                  <span className="text-xs text-gray-500 border border-gray-700 rounded px-2 py-0.5">
                    {cert.signing_scheme}
                    {cert.signing_scheme === "ML-DSA-65" && (
                      <span className="ml-1 text-purple-400">★ PQC FIPS 204</span>
                    )}
                  </span>
                  <span className="text-xs text-gray-500">{cert.solver_time_ms} ms</span>
                </div>
                <div className="text-white font-semibold">{cert.entity}</div>
                <div className="text-xs text-gray-500 space-y-0.5">
                  <div>Seed   <span className="text-gray-300">{cert.claim_seed}</span></div>
                  <div>Target <span className="text-gray-300">{cert.claim_target}</span></div>
                </div>
              </div>
            </div>

            {/* Axioms */}
            <div className="border border-gray-800 rounded-lg p-5 bg-[#0d0d14] space-y-3">
              <div className="text-xs text-gray-500 uppercase tracking-widest">Axioms Applied</div>
              <div className="flex flex-wrap gap-2">
                {cert.axioms_applied.map(ax => (
                  <div key={ax} className="border border-cyan-800 bg-cyan-950/30 rounded px-3 py-1.5">
                    <span className="text-cyan-400 font-bold text-xs">{ax}</span>
                    <span className="text-gray-400 text-xs ml-2">{AXIOM_LABELS[ax] ?? ax}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Derivation chain */}
            <div className="border border-gray-800 rounded-lg bg-[#0d0d14] overflow-hidden">
              <button
                onClick={() => setShowChain(v => !v)}
                className="w-full flex items-center justify-between px-5 py-4 hover:bg-white/5 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-500 uppercase tracking-widest">Derivation Chain</span>
                  <span className="text-xs text-gray-600">({cert.hop_count} hops)</span>
                </div>
                {showChain ? <ChevronUp className="w-4 h-4 text-gray-500" /> : <ChevronDown className="w-4 h-4 text-gray-500" />}
              </button>
              {showChain && (
                <div className="px-5 pb-5 space-y-3 border-t border-gray-800">
                  {cert.derivation_steps.length > 0 ? cert.derivation_steps.map(step => (
                    <div key={step.step} className="flex gap-4 text-sm">
                      <div className="shrink-0 text-cyan-600 font-bold w-14">Step {step.step}</div>
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="border border-cyan-800 text-cyan-400 text-xs px-1.5 py-0.5 rounded">{step.axiom}</span>
                          <span className="text-gray-500 text-xs">{step.tx_hash.slice(0, 18)}…</span>
                        </div>
                        <div className="text-gray-300 text-xs">{step.description}</div>
                      </div>
                    </div>
                  )) : (
                    <p className="text-gray-500 text-sm py-2">
                      Attribution proved by Z3 — graph is fully connected under stated axioms.
                    </p>
                  )}
                </div>
              )}
            </div>

            {/* Certificate */}
            <div className="border border-gray-800 rounded-lg p-5 bg-[#0d0d14] space-y-3">
              <div className="flex items-center justify-between">
                <div className="text-xs text-gray-500 uppercase tracking-widest">Signed Certificate</div>
                <button
                  onClick={() => copy(JSON.stringify(cert, null, 2))}
                  className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-white transition-colors"
                >
                  <Copy className="w-3.5 h-3.5" />
                  {copied ? "Copied!" : "Copy JSON"}
                </button>
              </div>
              <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-xs">
                {([
                  ["ID",        cert.certificate_id],
                  ["SHA-256",   cert.sha256.slice(0, 32) + "…"],
                  ["Signature", cert.signature.slice(0, 32) + "…"],
                  ["PubKey FP", cert.pubkey_fp],
                  ["Scheme",    cert.signing_scheme],
                  ["Issued",    cert.timestamp],
                  ["Issuer",    cert.issuer],
                ] as [string, string][]).map(([k, v]) => (
                  <div key={k} className="flex gap-3">
                    <span className="text-gray-500 w-20 shrink-0">{k}</span>
                    <span className="text-gray-300 break-all">{v}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Compare */}
            <div className="border border-gray-800 rounded-lg p-5 bg-[#0d0d14] space-y-4">
              <div className="text-xs text-gray-500 uppercase tracking-widest">
                VERDICT ENGINE vs Chainalysis Reactor
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="border border-gray-700 rounded p-4 space-y-2">
                  <div className="text-xs text-gray-500 font-semibold">CHAINALYSIS REACTOR</div>
                  {([
                    ["Result",       `${cert.entity} (high confidence)`],
                    ["Methodology",  "PROPRIETARY — not disclosed"],
                    ["Reproducible", "NO"],
                    ["Falsifiable",  "NO"],
                    ["Error rate",   "Unknown (admitted under oath)"],
                    ["Court status", "Expert opinion — Daubert fragile"],
                    ["Signed cert",  "NO"],
                  ] as [string, string][]).map(([k, v]) => (
                    <div key={k} className="flex gap-2 text-xs">
                      <span className="text-gray-500 w-24 shrink-0">{k}</span>
                      <span className={v === "NO" ? "text-red-400" : "text-gray-300"}>{v}</span>
                    </div>
                  ))}
                </div>
                <div className="border border-green-800 rounded p-4 space-y-2">
                  <div className="text-xs text-green-400 font-semibold">VERDICT ENGINE</div>
                  {([
                    ["Result",       cert.proof_status],
                    ["Methodology",  cert.axioms_applied.join(" + ") + " (public)"],
                    ["Reproducible", "YES — full trace"],
                    ["Falsifiable",  "YES — axiom set stated"],
                    ["Error rate",   "0% for stated axioms"],
                    ["Court status", "Mathematical proof — Z3 UNSAT"],
                    ["Signed cert",  `YES — ${cert.signing_scheme}`],
                  ] as [string, string][]).map(([k, v]) => (
                    <div key={k} className="flex gap-2 text-xs">
                      <span className="text-gray-500 w-24 shrink-0">{k}</span>
                      <span className={
                        v.startsWith("YES") || v === "PROVED" || v === "0% for stated axioms"
                          ? "text-green-400"
                          : "text-gray-300"
                      }>{v}</span>
                    </div>
                  ))}
                </div>
              </div>
              <p className="text-xs text-gray-600">
                Source: United States v. Sterlingov (2024) · INTERPOL/Basel Institute Conference 2025 ·
                Daubert v. Merrell Dow (1993)
              </p>
            </div>

            {/* Raw JSON toggle */}
            <div className="border border-gray-800 rounded-lg bg-[#0d0d14] overflow-hidden">
              <button
                onClick={() => setShowRaw(v => !v)}
                className="w-full flex items-center justify-between px-5 py-3 text-xs text-gray-500 hover:bg-white/5 transition-colors"
              >
                <span className="uppercase tracking-widest">Raw Certificate JSON</span>
                {showRaw ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
              {showRaw && (
                <pre className="border-t border-gray-800 px-5 py-4 text-xs text-gray-400 overflow-x-auto">
                  {JSON.stringify(cert, null, 2)}
                </pre>
              )}
            </div>

          </div>
        )}

        {/* Footer */}
        <footer className="border-t border-gray-800 pt-6 text-xs text-gray-600 flex items-center justify-between">
          <span>VERDICT ENGINE v1.0.0 · EVIDENTUM — Proof Intelligence</span>
          <a
            href="https://github.com/dom-omg/verdict-engine"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1 hover:text-gray-400 transition-colors"
          >
            GitHub <ExternalLink className="w-3 h-3" />
          </a>
        </footer>
      </div>
    </main>
  );
}
