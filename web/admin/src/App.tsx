import { Fragment, useEffect, useState, useRef, type FormEvent } from "react";

type Rule = { service_name?: string; guid: string; port: number; path?: string; allowed_networks?: string[] };
type AccessEntry = { port: number; ip: string; expires_at: string };
type AccessStatus = { ip: string; entries: AccessEntry[] };

function remainingTime(expiresAt: string, now: number) {
  const seconds = Math.max(0, Math.ceil((Date.parse(expiresAt) - now) / 1000));
  if (!seconds) return "";
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  return hours ? `${hours} ч ${minutes} мин` : `${minutes} мин ${secs} сек`;
}

type Config = {
  listen_addr: string;
  public_base_url: string;
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
  return hex.toUpperCase();
}

export default function App() {
  const [authenticated, setAuthenticated] = useState(false);
  const [checking, setChecking] = useState(true);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [config, setConfig] = useState<Config | null>(null);
  const [busy, setBusy] = useState(false);
  const [accessStatus, setAccessStatus] = useState<AccessStatus | null>(null);
  const [now, setNow] = useState(Date.now());
  const [page, setPage] = useState<"rules" | "settings">("rules");
  const [expandedRule, setExpandedRule] = useState<number | null>(null);
  const [expandedPath, setExpandedPath] = useState<number | null>(null);
  const importInput = useRef<HTMLInputElement>(null);
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

  useEffect(() => {
    if (!authenticated) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [authenticated]);

  useEffect(() => {
    if (!authenticated) return;
    void loadAccessStatus();
    const timer = window.setInterval(() => { void loadAccessStatus(); }, 30000);
    return () => window.clearInterval(timer);
  }, [authenticated]);

  async function loadAccessStatus() {
    try {
      const response = await api("/api/access/current-ip/status");
      setAccessStatus(await response.json() as AccessStatus);
    } catch { setAccessStatus(null); }
  }

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

  async function exportSettings() {
    setError(""); setMessage("");
    try {
      const response = await api("/api/config");
      const saved = await response.json() as Config;
      const blob = new Blob([JSON.stringify({ format: "portkeeper-settings", version: 1, config: saved }, null, 2) + "\n"], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url; anchor.download = "portkeeper-settings.json";
      document.body.appendChild(anchor); anchor.click(); anchor.remove();
      URL.revokeObjectURL(url);
      setMessage("Экспортирована сохранённая конфигурация.");
    } catch (e) { setError(String(e)); }
  }

  async function importSettings(file: File) {
    setError(""); setMessage("");
    try {
      if (file.size > 1024 * 1024) throw new Error("JSON-файл слишком большой (максимум 1 МБ).");
      const payload: unknown = JSON.parse(await file.text());
      if (!payload || typeof payload !== "object") throw new Error("Неверный формат JSON.");
      const envelope = payload as Record<string, unknown>;
      if (envelope.format !== "portkeeper-settings" || envelope.version !== 1 || !envelope.config || typeof envelope.config !== "object")
        throw new Error("Неподдерживаемый формат или версия экспорта PortKeeper.");
      const imported = envelope.config as Config;
      if (!Array.isArray(imported.access) || !imported.admin || typeof imported.default_ttl !== "string" || typeof imported.public_base_url !== "string")
        throw new Error("Файл не содержит корректную конфигурацию.");
      if (!window.confirm("Импорт заменит текущие настройки и правила доступа. Конфигурация будет сразу сохранена и применена. Продолжить?")) return;
      setBusy(true);
      const response = await api("/api/config", { method: "PUT", body: JSON.stringify(imported) });
      const result = await response.json();
      setConfig(result.config); setExpandedRule(null); setExpandedPath(null);
      setMessage("Настройки импортированы и применены." + (result.restart_required ? " Для применения TLS-настроек нужен перезапуск PortKeeper." : ""));
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); if (importInput.current) importInput.current.value = ""; }
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

  async function copyGuidURL(guid: string) {
    if (!config?.public_base_url) {
      setError("Сначала укажи публичный URL API в основных параметрах.");
      return;
    }
    const url = `${config.public_base_url.replace(/\/+$/, "")}/${encodeURIComponent(guid)}`;
    try {
      await navigator.clipboard.writeText(url);
      setError("");
      setMessage(`URL для GUID скопирован: ${url}`);
    } catch {
      setError("Не удалось скопировать URL. Проверь, что админка открыта по HTTPS и браузеру разрешён доступ к буферу обмена.");
    }
  }

  function openService(port: number, path = "/") {
    if (!Number.isInteger(port) || port < 1 || port > 65535) { setError("Некорректный TCP-порт."); return; }
    const url = `https://${window.location.hostname.includes(":") ? `[${window.location.hostname}]` : window.location.hostname}:${port}${path || "/"}`;
    window.open(url, "_blank", "noopener,noreferrer");
  }

  async function grantCurrentIP(port: number) {
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await api("/api/access/current-ip", { method: "POST", body: JSON.stringify({ port }) });
      const result = await response.json();
      setAccessStatus(previous => ({ ip: result.ip, entries: [...(previous && previous.ip === result.ip ? previous.entries.filter(entry => entry.port !== result.port) : []), { port: result.port, ip: result.ip, expires_at: result.expires_at }] }));
      setNow(Date.now());
      setMessage(`Доступ к TCP-порту ${result.port} открыт для IP ${result.ip} до ${new Date(result.expires_at).toLocaleString()}.`);
    } catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }

  async function logout() {
    try { await api("/api/logout", { method: "POST" }); } finally { setAuthenticated(false); setConfig(null); setAccessStatus(null); }
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
  

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand"><span className="brand-icon">P</span><div><b>PortKeeper</b><small>Administration</small></div></div>
        <div className="top-actions"><span className="status"><i /> Local instance</span><button className="secondary compact" onClick={logout}>Выйти</button></div>
      </header>
      <main className="content">
        <nav className="page-nav" aria-label="Разделы"><button className={page === "rules" ? "active" : "secondary"} onClick={() => setPage("rules")}>Access Rules</button><button className={page === "settings" ? "active" : "secondary"} onClick={() => setPage("settings")}>Настройки</button></nav>
        <div className="page-heading"><div><p className="eyebrow">SERVER CONTROL</p><h1>{page === "rules" ? "Access Rules" : "Настройки"}</h1><p className="muted">{page === "rules" ? "Управление доступом к TCP-портам" : "Параметры PortKeeper и firewall"}</p></div></div>
        {error && <div className="notice error">{error}</div>}
        {message && <div className="notice success">{message}</div>}
        {page === "settings" && <>
          <section className="panel settings-transfer">
            <div><h2>Экспорт и импорт</h2><p className="muted">JSON включает настройки и Access Rules (в том числе GUID, CIDR и Path). Пароль администратора и сессии не экспортируются. Импорт сразу применяет правила.</p></div>
            <div className="transfer-actions">
              <button className="secondary compact" disabled={busy} onClick={exportSettings}>Экспорт JSON</button>
              <button className="secondary compact" disabled={busy} onClick={() => importInput.current?.click()}>Импорт JSON</button>
              <input ref={importInput} className="hidden-file" type="file" accept=".json,application/json" aria-label="Файл импорта PortKeeper" onChange={e => { const file = e.target.files?.[0]; if (file) void importSettings(file); }} />
            </div>
          </section>
          <section className="panel">
          <div className="section-title"><div><h2>Основные параметры</h2><p className="muted">Параметры API и ограничение частоты запросов</p></div></div>
          <div className="form-grid">
            <label>API Listen Address<input value={config.listen_addr} disabled /></label>
            <label className="wide">Public API URL<input value={config.public_base_url || ""} placeholder="https://vpn.example.com:8787" onChange={(e) => setConfig({ ...config, public_base_url: e.target.value })} /><small className="muted">Публичный адрес API с протоколом и портом, без завершающего слеша. Используется для создания ссылок вида URL/GUID.</small></label>
            <label>Default TTL<input value={config.default_ttl} onChange={(e) => setConfig({ ...config, default_ttl: e.target.value })} /></label>
            <label>Rate limit requests<input type="number" min="1" value={config.rate_limit_requests} onChange={(e) => setConfig({ ...config, rate_limit_requests: Number(e.target.value) })} /></label>
            <label>Rate limit window<input value={config.rate_limit_window} onChange={(e) => setConfig({ ...config, rate_limit_window: e.target.value })} /></label>
            <label className="wide">State file<input value={config.state_file} disabled /></label>
          </div>
        </section>
          <div className="footer-actions"><button className="secondary" onClick={loadConfig} disabled={busy}>Отменить изменения</button><button onClick={saveConfig} disabled={busy}>Сохранить настройки</button></div>
        </>}
        {page === "rules" && <section className="panel">
          <div className="section-title"><div><h2>Правила доступа</h2><p className="muted">Изменения применяются после сохранения конфигурации.</p></div><button className="secondary compact" onClick={() => { setConfig({ ...config, access: [...config.access, { service_name: "", guid: newGuid(), port: 8080, path: "/", allowed_networks: [] }] }); setExpandedRule(config.access.length); }}>＋ Добавить правило</button></div>
          <div className="table-scroll"><table className="access-table"><thead><tr><th>Сервис</th><th>GUID</th><th>TCP-порт</th><th>CIDR</th><th>Действия</th></tr></thead><tbody>
            {config.access.map((rule, index) => <Fragment key={index}><tr><td><input aria-label="Название сервиса" value={rule.service_name ?? ""} maxLength={120} placeholder="Название" onChange={e => updateRule(index, { service_name: e.target.value })}/></td>
              <td><input className="guid-input" aria-label="GUID" value={rule.guid} spellCheck={false} onChange={e => updateRule(index, { guid: e.target.value })}/></td>
              <td><input className="port-input" aria-label="TCP-порт" type="number" min="1" max="65535" value={rule.port} onChange={e => updateRule(index, { port: Number(e.target.value) })}/></td>
              <td><button className="secondary compact cidr-toggle" aria-expanded={expandedRule === index} onClick={() => setExpandedRule(expandedRule === index ? null : index)}><span>{(rule.allowed_networks ?? []).length} сетей</span><span className="cidr-chevron" aria-hidden="true">{expandedRule === index ? "▴" : "▾"}</span></button></td>
              <td><div className="table-actions"><button className="secondary compact" onClick={() => copyGuidURL(rule.guid)} disabled={busy || !config.public_base_url} title="Скопировать URL GUID">Копировать URL</button><button className="secondary compact" onClick={() => grantCurrentIP(rule.port)} disabled={busy} title="Открыть для моего IP">Открыть IP</button>{(() => { const entry = accessStatus?.entries.find(item => item.port === rule.port && Date.parse(item.expires_at) > now); return entry ? <span className="access-remaining" title={`IP ${entry.ip}, до ${new Date(entry.expires_at).toLocaleString()}`}>● Доступен · {remainingTime(entry.expires_at, now)}</span> : null; })()}<button className="secondary compact" onClick={() => openService(rule.port, rule.path)} title="Открыть HTTPS-страницу сервиса в новой вкладке">Открыть в браузере</button><button className="secondary compact path-toggle" aria-label="Редактировать Path" title="Редактировать путь URL" aria-expanded={expandedPath === index} onClick={() => { setExpandedPath(expandedPath === index ? null : index); setExpandedRule(null); }}>▾</button><button className="icon-button danger-text delete-rule" title="Удалить правило" aria-label="Удалить правило" onClick={() => { setConfig({ ...config, access: config.access.filter((_, i) => i !== index) }); setExpandedRule(null); }}>×</button></div></td></tr>
              {expandedPath === index && <tr className="cidr-detail-row"><td colSpan={5}><div className="cidr-editor path-editor"><div className="section-title"><div><h3>Path — {rule.service_name || `порт ${rule.port}`}</h3><p className="muted">Путь после порта. Начинается с /; по умолчанию /.</p></div><button className="secondary compact" onClick={() => setExpandedPath(null)}>Свернуть</button></div><input aria-label="Path сервиса" value={rule.path ?? "/"} placeholder="/" onChange={e => updateRule(index, { path: e.target.value })} /></div></td></tr>}
              {expandedRule === index && <tr className="cidr-detail-row"><td colSpan={5}><div className="cidr-editor"><div className="section-title"><div><h3>CIDR — {rule.service_name || `порт ${rule.port}`}</h3><p className="muted">Постоянно разрешённые сети, по одной на строку. Временный доступ по GUID работает отдельно.</p></div><button className="secondary compact" onClick={() => setExpandedRule(null)}>Свернуть</button></div><textarea rows={5} spellCheck={false} placeholder={"160.79.104.0/21\n153.61.208.0/20"} value={(rule.allowed_networks ?? []).join("\n")} onChange={e => updateRule(index, { allowed_networks: e.target.value.split(/\r?\n/).map(x => x.trim()).filter(Boolean) })}/></div></td></tr>}
            </Fragment>)}
          </tbody></table></div>
          <div className="footer-actions"><button className="secondary" onClick={() => {loadConfig();setExpandedRule(null);}} disabled={busy}>Отменить изменения</button><button onClick={async () => {await saveConfig();}} disabled={busy}>{busy ? "Сохранение…" : "Сохранить конфигурацию"}</button></div>
        </section>}
        {page === "settings" && <>        <section className="panel firewall-panel">
          <div><h2>Firewall</h2><p className="muted">Повторно создать цепочки и правила PortKeeper на основе текущего списка Access Rules, включая постоянные CIDR.</p></div>
          <button className="secondary" onClick={applyFirewall} disabled={busy}>Применить правила firewall</button>
        </section>
        <section className="security-note"><b>Административное соединение: {config.admin.https ? "HTTPS" : "HTTP"}</b><p>Админка слушает порт 8083. При HTTP логин и cookie передаются без TLS-шифрования. Для доступа через интернет настоятельно рекомендуется включить HTTPS и установить сертификат. Изменение TLS-параметров выполняется в config.yaml и требует перезапуска сервиса.</p></section>
        </>}
      </main>
    </div>
  );
}
