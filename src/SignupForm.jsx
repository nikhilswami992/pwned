import { useState, useCallback } from "react";

// ── Constants ──────────────────────────────────────────────────────────────────
const COMMON_PASSWORDS = [
  "password","123456","qwerty","letmein","admin","welcome","monkey",
  "dragon","master","sunshine","shadow","princess","football","baseball",
  "iloveyou","abc123","654321","superman","batman","trustno1","hello",
  "login","pass","secret","test","user","guest","root","changeme",
];

// ── Utility functions ──────────────────────────────────────────────────────────
function calcEntropy(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 32;
  return pool > 0 ? Math.round(pw.length * Math.log2(pool)) : 0;
}

function crackTime(entropy) {
  const secs = Math.pow(2, entropy) / 1e10;
  if (secs < 1)        return "less than a second";
  if (secs < 60)       return `${Math.round(secs)} seconds`;
  if (secs < 3600)     return `${(secs / 60).toFixed(1)} minutes`;
  if (secs < 86400)    return `${(secs / 3600).toFixed(1)} hours`;
  if (secs < 2592000)  return `${(secs / 86400).toFixed(1)} days`;
  if (secs < 31536000) return `${(secs / 2592000).toFixed(1)} months`;
  if (secs < 1e9)      return `${(secs / 31536000).toFixed(1)} years`;
  if (secs < 1e12)     return `${(secs / 31536000 / 1e6).toFixed(1)}M years`;
  return "centuries";
}

function getScore(entropy) {
  if (entropy === 0)  return { label: "",             color: "#94a3b8", pct: 0   };
  if (entropy < 28)   return { label: "Very Weak",    color: "#ef4444", pct: 15  };
  if (entropy < 40)   return { label: "Weak",         color: "#f97316", pct: 35  };
  if (entropy < 60)   return { label: "Fair",         color: "#eab308", pct: 58  };
  if (entropy < 80)   return { label: "Strong",       color: "#22c55e", pct: 80  };
  return               { label: "Very Strong",        color: "#10b981", pct: 100 };
}

function getChecks(pw) {
  const lower = pw.toLowerCase();
  return {
    length:  pw.length >= 12,
    upper:   /[A-Z]/.test(pw),
    lower:   /[a-z]/.test(pw),
    digit:   /[0-9]/.test(pw),
    symbol:  /[^a-zA-Z0-9]/.test(pw),
    noDict:  !COMMON_PASSWORDS.some((w) => lower.includes(w)),
  };
}

function getSuggestions(pw, checks) {
  const tips = [];
  if (!checks.length)  tips.push("Use at least 12 characters — length matters most.");
  if (!checks.upper)   tips.push("Add an uppercase letter (A–Z).");
  if (!checks.lower)   tips.push("Mix in some lowercase letters.");
  if (!checks.digit)   tips.push("Include at least one digit (0–9).");
  if (!checks.symbol)  tips.push("Add a special character like !, @, # or $.");
  if (!checks.noDict)  tips.push("Avoid common words or patterns.");
  if (/(.)\1{2,}/.test(pw)) tips.push("Avoid repeating the same character (e.g. aaa).");
  if (/123|abc|qwerty/i.test(pw)) tips.push("Avoid sequential patterns like 123 or abc.");
  return tips;
}

async function sha1Hex(str) {
  const buf = await crypto.subtle.digest(
    "SHA-1",
    new TextEncoder().encode(str)
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

async function checkBreach(password) {
  const hash   = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const res    = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const text   = await res.text();
  const match  = text.split("\n").find((l) => l.startsWith(suffix));
  return match ? parseInt(match.split(":")[1].trim(), 10) : 0;
}

// ── Sub-components ─────────────────────────────────────────────────────────────
function StrengthMeter({ pct, color }) {
  return (
    <div style={{ height: 4, background: "#e2e8f0", borderRadius: 2, overflow: "hidden", marginTop: 8 }}>
      <div
        style={{
          height: "100%",
          width: `${pct}%`,
          background: color,
          borderRadius: 2,
          transition: "width 0.35s ease, background 0.35s ease",
        }}
      />
    </div>
  );
}

function CheckItem({ ok, label }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: ok ? "#16a34a" : "#94a3b8" }}>
      <span style={{ fontSize: 14 }}>{ok ? "✓" : "○"}</span>
      {label}
    </div>
  );
}

function BreachBadge({ status, count }) {
  if (status === "idle")    return null;
  if (status === "loading") return <p style={badgeStyle("#f1f5f9", "#64748b")}>Checking breach database…</p>;
  if (status === "safe")    return <p style={badgeStyle("#f0fdf4", "#16a34a")}>✓ Not found in any known breaches</p>;
  if (status === "breach")  return <p style={badgeStyle("#fef2f2", "#dc2626")}>⚠ Found in {count.toLocaleString()} breaches — choose a different password</p>;
  return <p style={badgeStyle("#fef2f2", "#dc2626")}>Breach check failed. Check your connection.</p>;
}

function badgeStyle(bg, color) {
  return { margin: "8px 0 0", padding: "8px 12px", borderRadius: 8, background: bg, color, fontSize: 12, lineHeight: 1.5 };
}

// ── Password Field with analyzer ───────────────────────────────────────────────
function PasswordField({ value, onChange, onBreachResult }) {
  const [visible,      setVisible]      = useState(false);
  const [breachStatus, setBreachStatus] = useState("idle"); // idle | loading | safe | breach | error
  const [breachCount,  setBreachCount]  = useState(0);

  const entropy  = calcEntropy(value);
  const score    = getScore(entropy);
  const checks   = getChecks(value);
  const tips     = getSuggestions(value, checks);
  const allGood  = Object.values(checks).every(Boolean);

  const handleBreachCheck = useCallback(async () => {
    if (!value) return;
    setBreachStatus("loading");
    try {
      const count = await checkBreach(value);
      if (count > 0) {
        setBreachStatus("breach");
        setBreachCount(count);
        onBreachResult?.(false);
      } else {
        setBreachStatus("safe");
        onBreachResult?.(true);
      }
    } catch {
      setBreachStatus("error");
      onBreachResult?.(null);
    }
  }, [value, onBreachResult]);

  return (
    <div style={{ marginBottom: 20 }}>
      {/* Label row */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
        <label style={labelStyle}>Password</label>
        {value && (
          <span style={{ fontSize: 12, fontWeight: 600, color: score.color }}>
            {score.label} · {entropy} bits
          </span>
        )}
      </div>

      {/* Input */}
      <div style={{ position: "relative" }}>
        <input
          type={visible ? "text" : "password"}
          value={value}
          onChange={(e) => { onChange(e.target.value); setBreachStatus("idle"); }}
          placeholder="Create a strong password"
          autoComplete="new-password"
          style={{ ...inputStyle, paddingRight: 44 }}
        />
        <button
          type="button"
          onClick={() => setVisible((v) => !v)}
          style={eyeBtnStyle}
          aria-label={visible ? "Hide password" : "Show password"}
        >
          {visible ? "🙈" : "👁"}
        </button>
      </div>

      {/* Strength meter */}
      {value && <StrengthMeter pct={score.pct} color={score.color} />}

      {/* Crack time */}
      {value && (
        <p style={{ fontSize: 11, color: "#94a3b8", marginTop: 5 }}>
          Estimated crack time: <strong style={{ color: "#64748b" }}>{crackTime(entropy)}</strong> at 10B guesses/sec
        </p>
      )}

      {/* Criteria checklist */}
      {value && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "5px 16px", marginTop: 10 }}>
          <CheckItem ok={checks.length} label="12+ characters" />
          <CheckItem ok={checks.upper}  label="Uppercase letter" />
          <CheckItem ok={checks.lower}  label="Lowercase letter" />
          <CheckItem ok={checks.digit}  label="Digit (0–9)" />
          <CheckItem ok={checks.symbol} label="Special character" />
          <CheckItem ok={checks.noDict} label="Not a common word" />
        </div>
      )}

      {/* Suggestions */}
      {tips.length > 0 && value && (
        <ul style={{ margin: "10px 0 0", paddingLeft: 16, fontSize: 12, color: "#64748b", lineHeight: 1.8 }}>
          {tips.map((t, i) => <li key={i}>{t}</li>)}
        </ul>
      )}

      {/* Breach check */}
      {value && allGood && (
        <>
          <button type="button" onClick={handleBreachCheck} style={breachBtnStyle}>
            Check breach database (HaveIBeenPwned)
          </button>
          <BreachBadge status={breachStatus} count={breachCount} />
        </>
      )}
    </div>
  );
}

// ── Shared styles ──────────────────────────────────────────────────────────────
const labelStyle = { fontSize: 14, fontWeight: 500, color: "#374151" };

const inputStyle = {
  width: "100%", padding: "10px 14px", fontSize: 15,
  border: "1px solid #d1d5db", borderRadius: 8,
  outline: "none", boxSizing: "border-box",
  fontFamily: "inherit", color: "#111827",
  background: "#fff", transition: "border-color 0.15s",
};

const eyeBtnStyle = {
  position: "absolute", right: 12, top: "50%", transform: "translateY(-50%)",
  background: "none", border: "none", cursor: "pointer", fontSize: 16, lineHeight: 1,
};

const breachBtnStyle = {
  marginTop: 10, padding: "6px 14px", fontSize: 12,
  border: "1px solid #d1d5db", borderRadius: 6,
  background: "#f8fafc", cursor: "pointer", color: "#374151",
};

// ── Main SignupForm component ───────────────────────────────────────────────────
export default function SignupForm({ onSubmit }) {
  const [form, setForm] = useState({ name: "", email: "", password: "", confirm: "" });
  const [breachSafe, setBreachSafe]   = useState(null);
  const [submitted,  setSubmitted]    = useState(false);
  const [errors,     setErrors]       = useState({});

  const entropy  = calcEntropy(form.password);
  const checks   = getChecks(form.password);
  const allGood  = Object.values(checks).every(Boolean);
  const isStrong = entropy >= 60 && allGood;

  function validate() {
    const e = {};
    if (!form.name.trim())                    e.name     = "Name is required.";
    if (!/\S+@\S+\.\S+/.test(form.email))    e.email    = "Enter a valid email.";
    if (!isStrong)                            e.password = "Password does not meet all requirements.";
    if (form.password !== form.confirm)       e.confirm  = "Passwords do not match.";
    return e;
  }

  function handleChange(field) {
    return (val) => setForm((f) => ({ ...f, [field]: val }));
  }

  function handleInputChange(field) {
    return (e) => setForm((f) => ({ ...f, [field]: e.target.value }));
  }

  function handleSubmit(e) {
    e.preventDefault();
    const errs = validate();
    setErrors(errs);
    if (Object.keys(errs).length === 0) {
      setSubmitted(true);
      onSubmit?.({ name: form.name, email: form.email });
    }
  }

  if (submitted) {
    return (
      <div style={cardStyle}>
        <div style={{ textAlign: "center", padding: "2rem 0" }}>
          <div style={{ fontSize: 40, marginBottom: 12 }}>✅</div>
          <h2 style={{ fontSize: 20, fontWeight: 600, color: "#111827", marginBottom: 8 }}>Account created!</h2>
          <p style={{ color: "#6b7280", fontSize: 14 }}>Welcome, {form.name}. Your account is secure.</p>
        </div>
      </div>
    );
  }

  return (
    <div style={cardStyle}>
      <h1 style={{ fontSize: 22, fontWeight: 700, color: "#111827", marginBottom: 4 }}>Create account</h1>
      <p style={{ fontSize: 14, color: "#6b7280", marginBottom: 24 }}>Fill in your details to get started.</p>

      <form onSubmit={handleSubmit} noValidate>
        {/* Name */}
        <div style={{ marginBottom: 18 }}>
          <label style={labelStyle}>Full name</label>
          <input
            type="text" value={form.name} onChange={handleInputChange("name")}
            placeholder="Jane Doe" style={{ ...inputStyle, marginTop: 6 }}
          />
          {errors.name && <p style={errStyle}>{errors.name}</p>}
        </div>

        {/* Email */}
        <div style={{ marginBottom: 18 }}>
          <label style={labelStyle}>Email address</label>
          <input
            type="email" value={form.email} onChange={handleInputChange("email")}
            placeholder="jane@example.com" style={{ ...inputStyle, marginTop: 6 }}
          />
          {errors.email && <p style={errStyle}>{errors.email}</p>}
        </div>

        {/* Password with analyzer */}
        <PasswordField
          value={form.password}
          onChange={handleChange("password")}
          onBreachResult={setBreachSafe}
        />
        {errors.password && <p style={{ ...errStyle, marginTop: -12, marginBottom: 12 }}>{errors.password}</p>}

        {/* Confirm password */}
        <div style={{ marginBottom: 24 }}>
          <label style={labelStyle}>Confirm password</label>
          <input
            type="password" value={form.confirm} onChange={handleInputChange("confirm")}
            placeholder="Re-enter your password" style={{ ...inputStyle, marginTop: 6 }}
          />
          {errors.confirm && <p style={errStyle}>{errors.confirm}</p>}
          {form.confirm && form.password === form.confirm && (
            <p style={{ fontSize: 12, color: "#16a34a", marginTop: 5 }}>✓ Passwords match</p>
          )}
        </div>

        <button
          type="submit"
          disabled={!isStrong}
          style={{
            ...submitBtnStyle,
            opacity: isStrong ? 1 : 0.45,
            cursor: isStrong ? "pointer" : "not-allowed",
          }}
        >
          Create account
        </button>

        <p style={{ fontSize: 12, color: "#9ca3af", textAlign: "center", marginTop: 16 }}>
          Your password is hashed client-side before any breach check. We never see it.
        </p>
      </form>
    </div>
  );
}

const cardStyle = {
  maxWidth: 480, margin: "0 auto", padding: "2rem",
  background: "#fff", borderRadius: 16,
  border: "1px solid #e5e7eb", fontFamily: "system-ui, sans-serif",
};

const errStyle  = { fontSize: 12, color: "#dc2626", marginTop: 5 };

const submitBtnStyle = {
  width: "100%", padding: "12px", fontSize: 15, fontWeight: 600,
  background: "#111827", color: "#fff", border: "none",
  borderRadius: 8, cursor: "pointer", transition: "opacity 0.2s",
};