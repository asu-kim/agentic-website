import React, { useEffect, useState } from "react";
import './App.css';

export default function Dashboard() {
  const [agent, setAgent] = useState(() => localStorage.getItem("agentname") || "UnknownAgent");
  const [trust, setTrust] = useState(() => localStorage.getItem("agent_trust") || "low");
  const [results, setResults] = useState({});
  const [remainingMs, setRemainingMs] = useState(() => {
    const exp = parseInt(localStorage.getItem("agent_session_expires_at") || "0", 10);
    return exp > 0 ? Math.max(0, exp - Date.now()) : 0;
  });

  const API_BASE = 'http://127.0.0.1:5000';

  useEffect(() => {
    const id = setInterval(() => {
      const exp = parseInt(localStorage.getItem("agent_session_expires_at") || "0", 10);
      if (!exp) { setRemainingMs(0); return; }
      const rem = Math.max(0, exp - Date.now());
      setRemainingMs(rem);
      if (rem <= 0) {
        localStorage.removeItem("agent_session_expires_at");
        localStorage.removeItem("agent_trust");
        localStorage.removeItem("agentname");
        window.location.replace("/agent-login");
      }
    }, 1000);
    return () => clearInterval(id);
  }, []);

  const formatRemaining = (ms) => {
    if (!ms || ms <= 0) return "expired";
    const s = Math.floor(ms / 1000);
    const hh = Math.floor(s / 3600).toString().padStart(2, "0");
    const mm = Math.floor((s % 3600) / 60).toString().padStart(2, "0");
    const ss = Math.floor(s % 60).toString().padStart(2, "0");
    return `${hh}:${mm}:${ss}`;
  };

  const callScope = async (scope) => {
    const headers = {
      "X-user": localStorage.getItem("username") || 'user', // demo header
      "X-Trust-Level": trust,
    };
    try {
      const res = await fetch(`${API_BASE}/api/resource/${scope}`, { headers });
      const text = await res.text();
      let body; try { body = JSON.parse(text); } catch { body = text; }
      setResults((r) => ({
        ...r,
        [scope]: { status: res.status, body }
      }));
    } catch (e) {
      setResults((r) => ({
        ...r,
        [scope]: { status: "network-error", body: String(e) }
      }));
    }
  };

  const scopes = [
    { key: "email", label: "Email" },
    { key: "address", label: "Address" },
    { key: "cardNumber", label: "Card Number" },
    { key: "phone", label: "Phone Number" },
  ];


  const [purchase, setPurchase] = useState({
    item: "",
    address: "",
    card: "",
    phone: "",
  });
  const [purchaseError, setPurchaseError] = useState("");
  const [purchaseSuccess, setPurchaseSuccess] = useState("");


  const onlyDigits = (s) => s.replace(/\D/g, "");

  const submitMockPurchase = async (e) => {
    e.preventDefault();
    setPurchaseError("");
    setPurchaseSuccess("");


    const { item, address, card, phone } = purchase;
    if (!item.trim() || !address.trim() || !card.trim() || !phone.trim()) {
      setPurchaseError("Please fill out all fields.");
      return;
    }

    const cardDigits = onlyDigits(card);
    if (cardDigits.length < 12 || cardDigits.length > 19) {
      setPurchaseError("Card number length looks invalid (must be 12–19 digits).");
      return;
    }
    const phoneDigits = onlyDigits(phone);
    if (phoneDigits.length < 7) {
      setPurchaseError("Phone number length looks invalid.");
      return;
    }

    setPurchaseSuccess(`Payment completed (mock) for "${item.trim()}".`);
    setPurchase({ item: "", address: "", card: "", phone: "" });

  };

  return (
    <div className="access-wrap">
      <h1 className="title">Agent Dashboard</h1>
      <p className="subtle">
        Hello, <span className="mono">{agent}</span>
      </p>
      <p className="subtle">
        Trust level: <span className="mono">{trust}</span>
      </p>
      <p className="subtle">
        Session remaining: <span className="mono">{formatRemaining(remainingMs)}</span>
      </p>

      <div
        className="grid"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(350px, 1fr))",
          gap: "20px",
        }}
      >
        {scopes.map(({ key, label }) => {
          const r = results[key];
          return (
            <div key={key} id={`card-${key}`} className="card" style={{ border: '1px solid #eee', borderRadius: 12, padding: 12 }}>
              <h3 id={`card-label-${key}`} style={{ marginTop: 0 }}>{label}</h3>
              <button className="btn primary" id={`btn-request-${key}`} onClick={() => callScope(key)}>
                Request {label}
              </button>
              {r && (
                <div id={`result-${key}`} style={{ marginTop: 8 }}>
                  <div className="subtle">
                    Status: <span className="mono">{String(r.status)}</span>
                  </div>
                  <pre className="code-block" style={{ marginTop: 6 }}>
                    {JSON.stringify(r.body, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          );
        })}

        <div id="card-purchase" className="card" style={{ border: '1px solid #eee', borderRadius: 12, padding: 12 }}>
          <h3 style={{ marginTop: 0 }}>Simulated Critical Task: Purchase</h3>
          <p className="subtle" style={{ marginTop: -6 }}>
            Demo-only flow. No real payment will be processed.
          </p>

          <form onSubmit={submitMockPurchase} className="form" style={{ display: "grid", gap: 10, marginTop: 8 }}>
            <label className="label">Item</label>
            <input
              className="input"
              type="text"
              value={purchase.item}
              onChange={(e) => setPurchase((p) => ({ ...p, item: e.target.value }))}
              placeholder='e.g., "Wireless Mouse"'
              required
            />

            <label className="label">Shipping Address</label>
            <input
              className="input"
              type="text"
              value={purchase.address}
              onChange={(e) => setPurchase((p) => ({ ...p, address: e.target.value }))}
              placeholder="1234 E University Dr, Tempe, AZ ..."
              required
            />

            <label className="label">Card Number (mock)</label>
            <input
              className="input"
              type="text"
              inputMode="numeric"
              value={purchase.card}
              onChange={(e) => setPurchase((p) => ({ ...p, card: e.target.value }))}
              placeholder="4242 4242 4242 4242"
              required
            />

            <label className="label">Phone Number</label>
            <input
              className="input"
              type="tel"
              value={purchase.phone}
              onChange={(e) => setPurchase((p) => ({ ...p, phone: e.target.value }))}
              placeholder="480-555-0100"
              required
            />

            <button className="btn primary" type="submit">
              {"Submit Purchase (Mock)"}
            </button>

            {purchaseError && <div className="error" style={{ marginTop: 8 }}>{purchaseError}</div>}
            {purchaseSuccess && <div className="success" style={{ marginTop: 8 }}>{purchaseSuccess}</div>}

            {!purchaseSuccess && (
              <p className="hint" style={{ marginTop: 8 }}>
                For demonstration purposes only. There's no real-world payment.
              </p>
            )}
          </form>
        </div>
      </div>
    </div>
  );
}
