import { useEffect, useState, type FormEvent } from "react";

type Rule = { guid: string; port: number };
type Config = {
  listen_addr: string;
  default_ttl: string;
  state_file: string;
  rate_limit_requests: number;
  rate_limit_window: string;
  access: Rule[];
  admin: { enabled: boolean; listen_addr: string; https: boolean; tls_cert_file: string; tls_key_file: string };
};

async function api(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  headers.set("X-PortKeeper-Request", "1");
  if (init.body) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...init, headers, credentials: "same-origin" });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `HTTP ${response.status}`);
  }
  return response;
}

function newGuid() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export default function App() {
  const [authenticated, setAuthenticated] = useState(false);
  const [checking, setChecking] = useState(true);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [config, setConfig] = useState<Config | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    fetch("/api/session", { credentials: "same-origin" })
      .then((r) => setAuthenticated(r.ok))
      .catch(() => setAuthenticated(false))
      .finally(() => setChecking(false));
  }, []);

  useEffect(() => {
    if (authenticated) loadConfig();
  }, [authenticated]);

  async function loadConfig() {
    setError("");
    try {
      const response = await api("/api/config");
      setConfig(await response.json());
    } catch (e) { setError(String(e)); }
  }

  async function login(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      await api("/api/login", { method: "POST", body: JSON.stringify({ username, password }) });
      setPassword(""); setAuthenticated(true);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }

  async function saveConfig() {
    if (!config) return;
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await api("/api/config", { method: "PUT", body: JSON.stringify(config) });
      const result = await response.json();
      setConfig(result.config);
      setMessage("Конфигурация сохранена, правила firewall обновлены.");
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }

  async function applyFirewall() {
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await api("/api/firewall/apply", { method: "POST" });
      const result = await response.json();
      setMessage(`Правила PortKeeper применены для портов: ${result.ports.join(", ")}.`);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }

  async function logout() {
    try { await api("/api/logout", { method: "POST" }); } finally { setAuthenticated(false); setConfig(null); }
  }

  function updateRule(index: number, patch: Partial<Rule>) {
    if (!config) return;
    const access = config.access.map((rule, i) => i === index ? { ...rule, ...patch } : rule);
    setConfig({ ...config, access });
  }

  if (checking) return <main className="center"><div className="loader" /></main>;
  if (!authenticated) return (
    <main className="center">
      <form className="login panel" onSubmit={login}>
        <div className="brand"><span className="brand-icon">P</span><div><b>PortKeeper</b><small>Administration</small></div></div>
        <h1>Вход в админку</h1>
        <label>Логин<input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required /></label>
        <label>Пароль<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></label>
        {error && <p className="error">{error}</p>}
        <button disabled={busy}>{busy ? "Входим…" : "Войти"}</button>
        <p className="muted">Доступ только для локального администратора PortKeeper.</p>
      </form>
    </main>
  );

  if (!config) return <main className="center"><div className="panel">{error || "Загрузка конфигурации…"}</div></main>;
  const tlsPendingRestart = config.admin.https !== (window.location.protocol === "https:");

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand"><span className="brand-icon">P</span><div><b>PortKeeper</b><small>Administration</small></div></div>
        <div className="top-actions"><span className="status"><i /> Local instance</span><button className="secondary compact" onClick={logout}>Выйти</button></div>
      </header>
      <main className="content">
        <div className="page-heading"><div><p className="eyebrow">SERVER CONTROL</p><h1>Конфигурация</h1><p className="muted">Управление локальным экземпляром PortKeeper</p></div><span className="pill">Admin API · :8083</span></div>
        {error && <div className="notice error">{error}</div>}
        {message && <div className="notice success">{message}</div>}
        <section className="panel">
          <div className="section-title"><div><h2>Основные параметры</h2><p className="muted">Параметры API и ограничение частоты запросов</p></div></div>
          <div className="form-grid">
            <label>API Listen Address<input value={config.listen_addr} disabled /></label>
            <label>Default TTL<input value={config.default_ttl} onChange={(e) => setConfig({ ...config, default_ttl: e.target.value })} /></label>
            <label>Rate limit requests<input type="number" min="1" value={config.rate_limit_requests} onChange={(e) => setConfig({ ...config, rate_limit_requests: Number(e.target.value) })} /></label>
            <label>Rate limit window<input value={config.rate_limit_window} onChange={(e) => setConfig({ ...config, rate_limit_window: e.target.value })} /></label>
            <label className="wide">State file<input value={config.state_file} disabled /></label>
          </div>
        </section>
        <section className="panel">
          <div className="section-title"><div><h2>Access Rules</h2><p className="muted">GUID сопоставляется с TCP-портом, который открывается для IP вызывающего клиента на время TTL.</p></div><button className="secondary compact" onClick={() => setConfig({ ...config, access: [...config.access, { guid: newGuid(), port: 8080 }] })}>＋ Добавить правило</button></div>
          <div className="rules">
            {config.access.map((rule, index) => <div className="rule" key={index}>
              <div className="rule-number">{String(index + 1).padStart(2, "0")}</div>
              <label className="guid-field">GUID<input value={rule.guid} onChange={(e) => updateRule(index, { guid: e.target.value })} spellCheck={false} /></label>
              <label className="port-field">TCP Port<input type="number" min="1" max="65535" value={rule.port} onChange={(e) => updateRule(index, { port: Number(e.target.value) })} /></label>
              <button className="icon-button danger-text" title="Удалить правило" onClick={() => setConfig({ ...config, access: config.access.filter((_, i) => i !== index) })}>×</button>
            </div>)}
          </div>
          <div className="rule-note">Порт не становится общедоступным: firewall пропускает только IP-адреса, которым выдан временный доступ через соответствующий GUID.</div>
          <div className="footer-actions"><button className="secondary" onClick={loadConfig} disabled={busy}>Отменить изменения</button><button onClick={saveConfig} disabled={busy}>{busy ? "Сохранение…" : "Сохранить конфигурацию"}</button></div>
        </section>
        <section className="panel firewall-panel">
          <div><h2>Firewall</h2><p className="muted">Повторно создать цепочки и правила PortKeeper на основе текущего списка Access Rules.</p></div>
          <button className="secondary" onClick={applyFirewall} disabled={busy}>Применить правила firewall</button>
        </section>
        <section className="security-note"><b>Административное соединение: {config.admin.https ? "HTTPS" : "HTTP"}</b><p>Админка слушает порт 8083. При HTTP логин и cookie передаются без TLS-шифрования. Для доступа через интернет настоятельно рекомендуется включить HTTPS и установить сертификат. Изменение TLS-параметров выполняется в config.yaml и требует перезапуска сервиса.</p></section>
      </main>
    </div>
  );
}
