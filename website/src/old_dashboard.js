import React, { useEffect, useState} from "react";
import './App.css';


export default function Dashboard(){
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
      "X-user": localStorage.getItem("username") || 'user', //// 
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

  return (
    <div className="access-wrap">
      <h1 className="title">Dashboard</h1>
      <p className="subtle">Hello, <span className="mono">{agent}</span></p>
      <p className="subtle">Session remaining: <span className="mono">{formatRemaining(remainingMs)}</span></p>

      <div className="grid" style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(350px, 1fr))",
          gap: "20px",
        }}>
        {scopes.map(({key, label}) => {
          const r = results[key];
          return (
            <div key={key} id={`card-${key}`} className="card" style={{border:'1px solid #eee', borderRadius:12, padding:12}}>
              <h3 id={`card-label-${key}`} style={{marginTop:0}}>{label}</h3>
              <button className="btn primary" id={`btn-request-${key}`} onClick={() => callScope(key)}>Request {label}</button>
              {r && (
                <div id={`result-${key}`} style={{marginTop:8}}>
                  <div className="subtle">
                    Status: <span className="mono">{String(r.status)}</span>
                  </div>
                  <pre className="code-block" style={{marginTop:6}}>
                    {JSON.stringify(r.body, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>

    </div>
  );
}