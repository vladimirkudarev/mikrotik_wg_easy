package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh"
)

type Settings struct {
	RouterHost      string `json:"router_host"`
	RouterUser      string `json:"router_user"`
	RouterPort      string `json:"router_port"`
	SSHKey          string `json:"ssh_key"`
	WGInterface     string `json:"wg_interface"`
	ListenPort      string `json:"listen_port"`
	ClientCIDR      string `json:"client_cidr"`
	RouterAddress   string `json:"router_address"`
	Endpoint        string `json:"endpoint"`
	DNS             string `json:"dns"`
	AllowedIPs      string `json:"allowed_ips"`
	Keepalive       string `json:"keepalive"`
	WANInterfaceLst string `json:"wan_interface_list"`
}

type Client struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Address   string `json:"address"`
	Comment   string `json:"comment"`
	Config    string `json:"config"`
	Disabled  bool   `json:"disabled"`
	CreatedAt string `json:"created_at"`
	ConfigOK  bool   `json:"config_ok"`
}

type State struct {
	Settings Settings `json:"settings"`
	Clients  []Client `json:"clients"`
}

var (
	appHost       = env("APP_HOST", "0.0.0.0")
	appPort       = env("APP_PORT", "8080")
	appData       = env("APP_DATA", "/data")
	statePath     = filepath.Join(appData, "state.json")
	sessionTTL, _ = strconv.Atoi(env("APP_SESSION_TTL_SECONDS", "28800"))
	stateMu       sync.Mutex
	sessionsMu    sync.Mutex
	sessions      = map[string]session{}
	passwordHash  = passwordHashFromEnv()
)

type session struct {
	CSRF    string
	Expires time.Time
}

func defaults() Settings {
	return Settings{
		RouterHost: env("ROS_HOST", "172.17.0.1"), RouterUser: env("ROS_USER", "wg-easy"), RouterPort: env("ROS_PORT", "22"), SSHKey: env("ROS_SSH_KEY", "/data/id_ed25519"),
		WGInterface: env("WG_INTERFACE", "wg0"), ListenPort: env("WG_LISTEN_PORT", "13231"), ClientCIDR: env("WG_CLIENT_CIDR", "10.8.0.0/24"), RouterAddress: env("WG_ROUTER_ADDRESS", "10.8.0.1/24"),
		Endpoint: env("WG_ENDPOINT", ""), DNS: env("WG_DNS", "10.8.0.1"), AllowedIPs: env("WG_ALLOWED_IPS", "0.0.0.0/0"), Keepalive: env("WG_KEEPALIVE", "25"), WANInterfaceLst: env("WG_WAN_INTERFACE_LIST", "WAN"),
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashPassword(password string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	digest := pbkdf2.Key([]byte(password), salt, 310000, 32, sha256.New)
	return fmt.Sprintf("pbkdf2_sha256$310000$%s$%s", base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(digest))
}

func passwordHashFromEnv() string {
	if v := os.Getenv("APP_PASSWORD_HASH"); v != "" {
		return v
	}
	if v := os.Getenv("APP_PASSWORD"); v != "" {
		return hashPassword(v)
	}
	if os.Getenv("APP_INSECURE_DEV") == "1" {
		return hashPassword("admin")
	}
	return ""
}

func verifyPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	rounds, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	expected, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	actual := pbkdf2.Key([]byte(password), salt, rounds, len(expected), sha256.New)
	return hmac.Equal(actual, expected)
}

func loadState() (State, error) {
	stateMu.Lock()
	defer stateMu.Unlock()
	s := State{Settings: defaults()}
	raw, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, err
	}
	d := defaults()
	if s.Settings.RouterHost == "" {
		s.Settings = d
	}
	if s.Clients == nil {
		s.Clients = []Client{}
	}
	return s, nil
}

func saveState(s State) error {
	stateMu.Lock()
	defer stateMu.Unlock()
	if err := os.MkdirAll(appData, 0700); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(statePath, raw, 0600)
}

func validateSettings(s Settings) error {
	if _, err := strconv.Atoi(s.RouterPort); err != nil {
		return fmt.Errorf("router_port must be a number")
	}
	p, err := strconv.Atoi(s.ListenPort)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("listen_port must be between 1 and 65535")
	}
	if _, _, err := net.ParseCIDR(s.ClientCIDR); err != nil {
		return fmt.Errorf("invalid client_cidr: %w", err)
	}
	ip, _, err := net.ParseCIDR(s.RouterAddress)
	if err != nil || ip == nil {
		return fmt.Errorf("invalid router_address")
	}
	for _, part := range strings.Split(s.AllowedIPs, ",") {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(part)); err != nil {
			return fmt.Errorf("invalid allowed_ips: %w", err)
		}
	}
	for _, part := range strings.Split(s.DNS, ",") {
		if net.ParseIP(strings.TrimSpace(part)) == nil {
			return fmt.Errorf("invalid dns address")
		}
	}
	return nil
}

func rosQuote(v string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(v, `\`, `\\`), `"`, `\"`) + `"`
}

func runRouterOS(command string) (string, error) {
	st, err := loadState()
	if err != nil {
		return "", err
	}
	key, err := os.ReadFile(st.Settings.SSHKey)
	if err != nil {
		return "", err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return "", err
	}
	cfg := &ssh.ClientConfig{
		User:            st.Settings.RouterUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	conn, err := ssh.Dial("tcp", net.JoinHostPort(st.Settings.RouterHost, st.Settings.RouterPort), cfg)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	sess, err := conn.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(command)
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text == "" {
			text = err.Error()
		}
		return "", fmt.Errorf("%s", text)
	}
	if err := routerOutputError(text); err != nil {
		return "", err
	}
	return text, nil
}

func routerOutputError(out string) error {
	lower := strings.ToLower(strings.TrimSpace(out))
	if lower == "" {
		return nil
	}
	markers := []string{
		"failure:",
		"no such item",
		"input does not match",
		"expected end of command",
		"bad command name",
		"syntax error",
	}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("RouterOS error: %s", out)
		}
	}
	return nil
}

func validClientConfig(config string) bool {
	return strings.Contains(config, "[Interface]") &&
		strings.Contains(config, "PrivateKey") &&
		strings.Contains(config, "[Peer]") &&
		strings.Contains(config, "PublicKey") &&
		routerOutputError(config) == nil
}

func clientsWithStatus(clients []Client) []Client {
	out := make([]Client, len(clients))
	for i, c := range clients {
		c.ConfigOK = validClientConfig(c.Config)
		out[i] = c
	}
	return out
}

func ensureWireGuardInterface(name string) error {
	out, err := runRouterOS(fmt.Sprintf(`:put [:len [/interface/wireguard/find where name=%s]]`, rosQuote(name)))
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) != "1" {
		return fmt.Errorf("WireGuard interface %q не найден на MikroTik. Сначала нажмите \"Применить настройку\" или укажите существующий interface в настройках", name)
	}
	return nil
}

func peerExists(comment string) (bool, error) {
	out, err := runRouterOS(fmt.Sprintf(`:put [:len [/interface/wireguard/peers/find where comment=%s]]`, rosQuote(comment)))
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) != "0", nil
}

func peerClientConfig(comment string) (string, error) {
	cfg, err := runRouterOS(fmt.Sprintf(`/interface/wireguard/peers/show-client-config [find where comment=%s]`, rosQuote(comment)))
	if err != nil {
		return "", err
	}
	if !validClientConfig(cfg) {
		return "", fmt.Errorf("RouterOS вернул невалидный client config: %s", cfg)
	}
	return cfg, nil
}

func nextClientAddress(st State) (string, error) {
	ip, netw, err := net.ParseCIDR(st.Settings.ClientCIDR)
	if err != nil {
		return "", err
	}
	_ = ip
	routerIP, _, _ := net.ParseCIDR(st.Settings.RouterAddress)
	used := map[string]bool{}
	for _, c := range st.Clients {
		used[c.Address] = true
	}
	if out, err := runRouterOS("/interface/wireguard/peers/print terse"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			fields := map[string]string{}
			for _, field := range strings.Fields(line) {
				k, v, ok := strings.Cut(field, "=")
				if ok {
					fields[k] = strings.Trim(v, `"`)
				}
			}
			if fields["interface"] != st.Settings.WGInterface {
				continue
			}
			for _, key := range []string{"allowed-address", "client-address"} {
				for _, addr := range strings.Split(fields[key], ",") {
					addr = strings.TrimSpace(strings.Trim(addr, `"`))
					if addr != "" {
						used[addr] = true
					}
				}
			}
		}
	}
	broadcast := broadcastIP(netw)
	for candidate := append(net.IP(nil), netw.IP...); netw.Contains(candidate); incIP(candidate) {
		if candidate.Equal(netw.IP) || candidate.Equal(routerIP) || (broadcast != nil && candidate.Equal(broadcast)) {
			continue
		}
		addr := candidate.String() + "/32"
		if !used[addr] {
			return addr, nil
		}
	}
	return "", fmt.Errorf("no free client addresses")
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func broadcastIP(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	if ip == nil || len(n.Mask) != net.IPv4len {
		return nil
	}
	out := append(net.IP(nil), ip...)
	for i := range out {
		out[i] |= ^n.Mask[i]
	}
	return out
}

func bootstrapRouter() ([]map[string]string, error) {
	st, _ := loadState()
	if err := validateSettings(st.Settings); err != nil {
		return nil, err
	}
	s := st.Settings
	cmds := []string{
		fmt.Sprintf(`:if ([:len [/interface/wireguard/find where name=%s]] = 0) do={/interface/wireguard/add name=%s listen-port=%s comment="mikrotik-wg-easy"} else={/interface/wireguard/set [find where name=%s] listen-port=%s comment="mikrotik-wg-easy"}`, rosQuote(s.WGInterface), rosQuote(s.WGInterface), s.ListenPort, rosQuote(s.WGInterface), s.ListenPort),
		fmt.Sprintf(`:if ([:len [/ip/address/find where comment="mikrotik-wg-easy"]] = 0) do={/ip/address/add address=%s interface=%s comment="mikrotik-wg-easy"} else={/ip/address/set [find where comment="mikrotik-wg-easy"] address=%s interface=%s}`, rosQuote(s.RouterAddress), rosQuote(s.WGInterface), rosQuote(s.RouterAddress), rosQuote(s.WGInterface)),
		fmt.Sprintf(`:if ([:len [/ip/firewall/filter/find where comment="mikrotik-wg-easy: allow wireguard"]] = 0) do={/ip/firewall/filter/add chain=input action=accept protocol=udp dst-port=%s comment="mikrotik-wg-easy: allow wireguard"} else={/ip/firewall/filter/set [find where comment="mikrotik-wg-easy: allow wireguard"] chain=input action=accept protocol=udp dst-port=%s}`, s.ListenPort, s.ListenPort),
		fmt.Sprintf(`:if ([:len [/ip/firewall/nat/find where comment="mikrotik-wg-easy: full tunnel"]] = 0) do={/ip/firewall/nat/add chain=srcnat action=masquerade src-address=%s out-interface-list=%s comment="mikrotik-wg-easy: full tunnel"} else={/ip/firewall/nat/set [find where comment="mikrotik-wg-easy: full tunnel"] chain=srcnat action=masquerade src-address=%s out-interface-list=%s}`, rosQuote(s.ClientCIDR), rosQuote(s.WANInterfaceLst), rosQuote(s.ClientCIDR), rosQuote(s.WANInterfaceLst)),
	}
	if _, err := runRouterOS(strings.Join(cmds, "\n")); err != nil {
		return nil, err
	}
	res := []map[string]string{}
	for _, c := range cmds {
		res = append(res, map[string]string{"ok": "true", "command": c})
	}
	return res, nil
}

func createClient(name string) (Client, error) {
	if strings.TrimSpace(name) == "" {
		return Client{}, fmt.Errorf("client name is required")
	}
	st, _ := loadState()
	if err := ensureWireGuardInterface(st.Settings.WGInterface); err != nil {
		return Client{}, err
	}
	addr, err := nextClientAddress(st)
	if err != nil {
		return Client{}, err
	}
	id := randToken(12)
	comment := "mikrotik-wg-easy:" + id
	endpoint := st.Settings.Endpoint
	if endpoint == "" {
		endpoint = st.Settings.RouterHost
	}
	cmd := fmt.Sprintf(`/interface/wireguard/peers/add interface=%s name=%s private-key=auto allowed-address=%s client-address=%s client-dns=%s client-endpoint=%s client-keepalive=%s client-allowed-address=%s comment=%s`,
		rosQuote(st.Settings.WGInterface), rosQuote(name), rosQuote(addr), rosQuote(addr), rosQuote(st.Settings.DNS), rosQuote(endpoint+":"+st.Settings.ListenPort), st.Settings.Keepalive, rosQuote(st.Settings.AllowedIPs), rosQuote(comment))
	if _, err := runRouterOS(cmd); err != nil {
		return Client{}, err
	}
	exists, err := peerExists(comment)
	if err != nil {
		return Client{}, err
	}
	if !exists {
		return Client{}, fmt.Errorf("RouterOS не создал peer для клиента %q. Проверьте WireGuard interface и права пользователя wg-easy", name)
	}
	cfg, err := peerClientConfig(comment)
	if err != nil {
		_, _ = runRouterOS(fmt.Sprintf(`/interface/wireguard/peers/remove [find where comment=%s]`, rosQuote(comment)))
		return Client{}, err
	}
	c := Client{ID: id, Name: name, Address: addr, Comment: comment, Config: cfg, ConfigOK: true, CreatedAt: time.Now().Format(time.RFC3339)}
	st.Clients = append(st.Clients, c)
	return c, saveState(st)
}

func clientAction(id, action string) (any, error) {
	st, _ := loadState()
	for i, c := range st.Clients {
		if c.ID != id {
			continue
		}
		find := fmt.Sprintf(`[find where comment=%s]`, rosQuote(c.Comment))
		switch action {
		case "disable", "enable":
			exists, err := peerExists(c.Comment)
			if err != nil {
				return nil, err
			}
			if !exists {
				return nil, fmt.Errorf("peer клиента %q не найден на MikroTik. Можно удалить эту запись из сервиса и создать клиента заново", c.Name)
			}
			disabled := action == "disable"
			val := "no"
			if disabled {
				val = "yes"
			}
			if _, err := runRouterOS(fmt.Sprintf(`/interface/wireguard/peers/set %s disabled=%s`, find, val)); err != nil {
				return nil, err
			}
			st.Clients[i].Disabled = disabled
			return st.Clients[i], saveState(st)
		case "delete":
			exists, err := peerExists(c.Comment)
			if err != nil {
				return nil, err
			}
			if exists {
				if _, err := runRouterOS(fmt.Sprintf(`/interface/wireguard/peers/remove %s`, find)); err != nil {
					return nil, err
				}
			}
			st.Clients = append(st.Clients[:i], st.Clients[i+1:]...)
			return map[string]bool{"ok": true}, saveState(st)
		case "recreate", "verify":
			exists, err := peerExists(c.Comment)
			if err != nil {
				return nil, err
			}
			if !exists {
				return nil, fmt.Errorf("peer клиента %q не найден на MikroTik. Конфигурация не работает; удалите запись и создайте клиента заново", c.Name)
			}
			cfg, err := peerClientConfig(c.Comment)
			if err != nil {
				return nil, err
			}
			st.Clients[i].Config = cfg
			st.Clients[i].ConfigOK = true
			if err := saveState(st); err != nil {
				return nil, err
			}
			return map[string]any{"name": c.Name, "config": cfg, "ok": true}, nil
		}
	}
	return nil, http.ErrMissingFile
}

func withHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
}

func jsonResp(w http.ResponseWriter, v any) {
	withHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func errResp(w http.ResponseWriter, code int, err error) {
	withHeaders(w)
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func currentSession(r *http.Request) (string, session, bool) {
	c, err := r.Cookie("mwg_session")
	if err != nil {
		return "", session{}, false
	}
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	s, ok := sessions[c.Value]
	if !ok || time.Now().After(s.Expires) {
		delete(sessions, c.Value)
		return "", session{}, false
	}
	return c.Value, s, true
}

func requireAuth(w http.ResponseWriter, r *http.Request) (string, session, bool) {
	if passwordHash == "" {
		errResp(w, 503, fmt.Errorf("APP_PASSWORD_HASH or APP_PASSWORD is required"))
		return "", session{}, false
	}
	id, s, ok := currentSession(r)
	if !ok {
		errResp(w, 401, fmt.Errorf("authentication required"))
		return "", session{}, false
	}
	if r.Method != http.MethodGet && r.Header.Get("X-CSRF-Token") != s.CSRF {
		errResp(w, 403, fmt.Errorf("invalid csrf token"))
		return "", session{}, false
	}
	return id, s, true
}

var loginPage = `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MikroTik WireGuard Easy</title>
  <style>
    :root{color-scheme:light;--bg:#eef1f4;--panel:#fff;--text:#17202a;--muted:#5b6775;--line:#d8dee6;--primary:#1763c6;--primary-dark:#104f9f;--danger:#b42318;--shadow:0 18px 50px rgba(25,35,45,.14)}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:linear-gradient(145deg,#f7f9fb 0%,var(--bg) 100%);color:var(--text);letter-spacing:0}
    main{min-height:100vh;display:grid;place-items:center;padding:24px}
    .login{width:min(420px,100%);background:var(--panel);border:1px solid var(--line);border-radius:8px;box-shadow:var(--shadow);padding:28px}
    .brand{display:flex;align-items:center;gap:12px;margin-bottom:24px}.mark{width:38px;height:38px;border-radius:8px;background:#1763c6;color:#fff;display:grid;place-items:center;font-weight:800}.brand h1{font-size:20px;line-height:1.2;margin:0}.brand p{margin:4px 0 0;color:var(--muted);font-size:13px}
    label{display:block;font-size:13px;font-weight:650;margin-bottom:8px}input{width:100%;height:42px;border:1px solid #c8d0da;border-radius:6px;padding:0 12px;font:inherit;background:#fff;color:var(--text)}input:focus{outline:2px solid rgba(23,99,198,.22);border-color:var(--primary)}
    button{width:100%;height:42px;margin-top:16px;border:0;border-radius:6px;background:var(--primary);color:#fff;font:inherit;font-weight:700;cursor:pointer}button:hover{background:var(--primary-dark)}
    .error{margin:0 0 16px;padding:10px 12px;border:1px solid #f2b8b5;background:#fff4f2;color:var(--danger);border-radius:6px;font-size:13px}
  </style>
</head>
<body>
  <main>
    <form class="login" method="post" action="/">
      <div class="brand"><div class="mark">WG</div><div><h1>MikroTik WireGuard Easy</h1><p>Управление клиентами WireGuard</p></div></div>
      {{if .Error}}<p class="error">{{.Error}}</p>{{end}}
      <label for="password">Пароль администратора</label>
      <input id="password" name="password" type="password" autocomplete="current-password" autofocus>
      <button type="submit">Войти</button>
    </form>
  </main>
</body>
</html>`

var loginTemplate = template.Must(template.New("login").Parse(loginPage))

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MikroTik WireGuard Easy</title>
  <style>
    :root{color-scheme:light;--bg:#f2f4f7;--surface:#fff;--surface-2:#f8fafc;--text:#17202a;--muted:#627183;--line:#d9e0e8;--primary:#1763c6;--primary-dark:#104f9f;--ok:#147a4b;--warn:#9a6700;--danger:#b42318;--danger-bg:#fff4f2;--radius:8px}
    *{box-sizing:border-box}body{margin:0;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--bg);color:var(--text);letter-spacing:0}
    button,input{font:inherit}button{border:0;border-radius:6px;height:36px;padding:0 12px;background:var(--primary);color:#fff;font-weight:700;cursor:pointer;white-space:nowrap}button:hover{background:var(--primary-dark)}button.secondary{background:#fff;color:#253241;border:1px solid #c9d2dd}button.secondary:hover{background:#eef3f8}button.danger{background:var(--danger)}button:disabled{opacity:.55;cursor:not-allowed}
    a{color:var(--primary);font-weight:650;text-decoration:none}a:hover{text-decoration:underline}
    .shell{min-height:100vh}.topbar{background:#fff;border-bottom:1px solid var(--line)}.topbar-inner{max-width:1220px;margin:0 auto;padding:16px 24px;display:flex;align-items:center;justify-content:space-between;gap:16px}.brand{display:flex;align-items:center;gap:12px;min-width:0}.mark{width:36px;height:36px;border-radius:8px;background:var(--primary);color:#fff;display:grid;place-items:center;font-weight:800}.brand h1{font-size:18px;line-height:1.2;margin:0}.brand p{margin:3px 0 0;color:var(--muted);font-size:13px}.top-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
    main{max-width:1220px;margin:0 auto;padding:22px 24px 34px}.status{min-height:40px;margin-bottom:14px}.notice{display:none;border:1px solid var(--line);background:#fff;border-radius:8px;padding:10px 12px;font-size:14px}.notice.show{display:block}.notice.error{border-color:#f1aaa4;background:var(--danger-bg);color:var(--danger)}.notice.ok{border-color:#a7d8bf;background:#f1fbf5;color:var(--ok)}
    .layout{display:grid;grid-template-columns:minmax(0,1fr) 360px;gap:18px;align-items:start}.panel{background:var(--surface);border:1px solid var(--line);border-radius:8px;margin-bottom:18px}.panel-head{padding:16px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:12px}.panel-head h2{font-size:16px;margin:0}.panel-head p{margin:4px 0 0;color:var(--muted);font-size:13px}.panel-body{padding:18px}
    .settings-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.field label{display:block;margin-bottom:7px;font-size:12px;font-weight:750;color:#354254}.field input{width:100%;height:38px;border:1px solid #c8d0da;border-radius:6px;padding:0 10px;background:#fff;color:var(--text)}.field input:focus{outline:2px solid rgba(23,99,198,.2);border-color:var(--primary)}.hint{display:block;margin-top:2px;color:var(--muted);font-weight:600;line-height:1.25}
    .client-create{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px}.client-create input{height:38px;border:1px solid #c8d0da;border-radius:6px;padding:0 10px}
    table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 10px;border-bottom:1px solid #e7ecf2;vertical-align:middle}th{font-size:12px;text-transform:uppercase;color:var(--muted);font-weight:800}td{font-size:14px}.actions{display:flex;gap:7px;flex-wrap:wrap;justify-content:flex-end}.badge{display:inline-flex;align-items:center;height:24px;padding:0 8px;border-radius:999px;font-size:12px;font-weight:750}.badge.ok{background:#eaf7ef;color:var(--ok)}.badge.off{background:#fff7e6;color:var(--warn)}.empty{padding:28px;text-align:center;color:var(--muted);border:1px dashed #cbd4df;border-radius:8px;background:var(--surface-2)}
    .summary{display:grid;gap:10px}.summary-row{display:flex;justify-content:space-between;gap:12px;border-bottom:1px solid #e7ecf2;padding-bottom:10px}.summary-row:last-child{border-bottom:0;padding-bottom:0}.summary-row span:first-child{color:var(--muted);font-size:13px}.summary-row span:last-child{font-weight:750;text-align:right;overflow-wrap:anywhere}
    dialog{width:min(860px,calc(100vw - 28px));border:1px solid var(--line);border-radius:8px;padding:0;box-shadow:0 24px 70px rgba(20,28,38,.22)}dialog::backdrop{background:rgba(18,27,38,.45)}.modal-head{padding:16px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:12px}.modal-head h2{margin:0;font-size:16px}.modal-body{padding:18px;display:grid;grid-template-columns:260px minmax(0,1fr);gap:18px}.qr-box{display:grid;place-items:center;border:1px solid var(--line);border-radius:8px;background:#fff;min-height:260px}.qr-box img{width:236px;height:236px}.config{margin:0;min-height:260px;max-height:420px;overflow:auto;white-space:pre-wrap;word-break:break-word;background:#101722;color:#f8fbff;border-radius:8px;padding:14px;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
    @media (max-width:980px){.layout{grid-template-columns:1fr}.settings-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.modal-body{grid-template-columns:1fr}.qr-box{min-height:auto;padding:14px}}@media (max-width:640px){.topbar-inner,main{padding-left:14px;padding-right:14px}.topbar-inner{align-items:flex-start;flex-direction:column}.top-actions{width:100%}.top-actions button{flex:1}.settings-grid{grid-template-columns:1fr}.client-create{grid-template-columns:1fr}.actions{justify-content:flex-start}th:nth-child(2),td:nth-child(2){display:none}}
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar"><div class="topbar-inner"><div class="brand"><div class="mark">WG</div><div><h1>MikroTik WireGuard Easy</h1><p>WireGuard на RouterOS через контейнер</p></div></div><div class="top-actions"><button id="bootstrapBtn" type="button">Применить настройку</button><button id="logoutBtn" class="secondary" type="button">Выйти</button></div></div></header>
    <main>
      <div class="status"><div id="notice" class="notice"></div></div>
      <div class="layout">
        <section class="panel"><div class="panel-head"><div><h2>Настройки WireGuard</h2><p>Параметры сохраняются в контейнере и применяются к RouterOS по SSH</p></div><button id="saveBtn" class="secondary" type="button">Сохранить</button></div><div class="panel-body"><div id="settings" class="settings-grid"></div></div></section>
        <aside class="panel"><div class="panel-head"><div><h2>Состояние</h2><p>Текущие ключевые параметры</p></div></div><div class="panel-body"><div id="summary" class="summary"></div></div></aside>
        <section class="panel"><div class="panel-head"><div><h2>Клиенты</h2><p>Создание, QR-код, конфиг, отключение и удаление peer</p></div></div><div class="panel-body"><div class="client-create"><input id="clientName" placeholder="Например: iphone-vladimir" autocomplete="off"><button id="createBtn" type="button">Создать клиента</button></div><div id="clientTable"></div></div></section>
      </div>
    </main>
  </div>
  <dialog id="dlg"><div class="modal-head"><h2 id="title"></h2><button id="closeDlg" class="secondary" type="button">Закрыть</button></div><div class="modal-body"><div class="qr-box"><img id="qr" alt="QR-код WireGuard"></div><pre id="config" class="config"></pre></div></dialog>
  <script>
    let csrf="";
    const fieldMeta=[
      ["router_host","RouterOS host","SSH адрес RouterOS из контейнера"],
      ["router_user","RouterOS user","Пользователь для SSH"],
      ["router_port","SSH port","Обычно 22"],
      ["ssh_key","SSH key","Путь внутри контейнера"],
      ["wg_interface","Interface","Имя WireGuard interface"],
      ["listen_port","Listen port","UDP порт WireGuard"],
      ["client_cidr","Client CIDR","Пул адресов клиентов"],
      ["router_address","Router address","Адрес роутера в WG-сети"],
      ["endpoint","Endpoint","Публичный адрес, если отличается"],
      ["dns","DNS","DNS для клиентов"],
      ["allowed_ips","Allowed IPs","Full-tunnel: 0.0.0.0/0"],
      ["keepalive","Keepalive","Persistent keepalive"],
      ["wan_interface_list","WAN list","Interface list для NAT"]
    ];
    function esc(v){return String(v??"").replaceAll("&","&amp;").replaceAll('"',"&quot;").replaceAll("<","&lt;").replaceAll(">","&gt;")}
    function show(msg,type="ok"){notice.textContent=msg;notice.className="notice show "+type;clearTimeout(show.t);show.t=setTimeout(()=>notice.className="notice",4200)}
    async function api(p,o={}){const h={"content-type":"application/json",...(o.headers||{})};if(o.method&&o.method!="GET")h["x-csrf-token"]=csrf;const r=await fetch(p,{...o,headers:h});const t=await r.text();let d;try{d=t?JSON.parse(t):null}catch{d=t}if(!r.ok)throw new Error(d?.error||t||r.statusText);return d}
    function currentSettings(){const p={};fieldMeta.forEach(([k])=>p[k]=document.getElementById("s_"+k).value.trim());return p}
	    async function load(){csrf=(await api("/api/session")).csrf;const s=await api("/api/settings");settings.innerHTML=fieldMeta.map(([k,label,hint])=>'<div class="field"><label for="s_'+k+'"><span>'+esc(label)+'</span><span class="hint">'+esc(hint)+'</span></label><input id="s_'+k+'" value="'+esc(s[k])+'"></div>').join("");summary.innerHTML=[["Interface",s.wg_interface],["Client CIDR",s.client_cidr],["Endpoint",s.endpoint||s.router_host],["Allowed IPs",s.allowed_ips]].map(([k,v])=>'<div class="summary-row"><span>'+esc(k)+'</span><span>'+esc(v)+'</span></div>').join("");renderClients(await api("/api/clients"))}
	    function renderClients(rows){rows=rows||[];if(!rows.length){clientTable.innerHTML='<div class="empty">Клиентов пока нет. Создайте первого клиента и откройте QR-код для подключения.</div>';return}clientTable.innerHTML='<table><thead><tr><th>Имя</th><th>Адрес</th><th>Статус</th><th></th></tr></thead><tbody>'+rows.map(c=>{const ok=!!c.config_ok;const badge=!ok?'<span class="badge off">Ошибка</span>':('<span class="badge '+(c.disabled?"off":"ok")+'">'+(c.disabled?"Отключен":"Активен")+'</span>');const download=ok?'<a href="/api/clients/'+encodeURIComponent(c.id)+'/download">.conf</a>':'<span class="hint">нет .conf</span>';return '<tr><td><strong>'+esc(c.name)+'</strong></td><td>'+esc(c.address)+'</td><td>'+badge+'</td><td><div class="actions"><button class="secondary" type="button" data-action="show" data-id="'+esc(c.id)+'">QR / Config</button>'+download+'<button class="secondary" type="button" data-action="verify" data-id="'+esc(c.id)+'">Проверить</button><button class="secondary" type="button" data-action="'+(c.disabled?"enable":"disable")+'" data-id="'+esc(c.id)+'">'+(c.disabled?"Включить":"Отключить")+'</button><button class="secondary" type="button" data-action="recreate-config" data-id="'+esc(c.id)+'">Пересоздать</button><button class="danger" type="button" data-action="delete" data-id="'+esc(c.id)+'">Удалить</button></div></td></tr>'}).join("")+'</tbody></table>'}
    async function saveSettings(){await api("/api/settings",{method:"POST",body:JSON.stringify(currentSettings())});await load();show("Настройки сохранены")}
    async function bootstrap(){await saveSettings();await api("/api/bootstrap",{method:"POST",body:"{}"});show("Настройка RouterOS применена")}
    async function createClient(){const name=clientName.value.trim();if(!name){show("Введите имя клиента","error");return}const c=await api("/api/clients",{method:"POST",body:JSON.stringify({name})});clientName.value="";await load();await showClient(c.id)}
    async function showClient(id){const c=await api("/api/clients/"+id+"/config");title.textContent=c.name;config.textContent=c.config;qr.src="/api/clients/"+id+"/qr?ts="+Date.now();dlg.showModal()}
    async function act(id,a){const r=await api("/api/clients/"+id+"/"+a,{method:"POST",body:"{}"});await load();show(a==="verify"?"Проверка прошла: peer и config валидны":"Клиент обновлен");if(r.config){title.textContent=r.name;config.textContent=r.config;qr.src="/api/clients/"+id+"/qr?ts="+Date.now();dlg.showModal()}}
    async function delClient(id){if(!confirm("Удалить клиента и peer на MikroTik?"))return;await api("/api/clients/"+id,{method:"DELETE",body:"{}"});await load();show("Клиент удален")}
    async function logout(){await api("/logout",{method:"POST",body:"{}"});location.href="/"}
    clientTable.addEventListener("click",e=>{const b=e.target.closest("button[data-action]");if(!b)return;const id=b.dataset.id;const a=b.dataset.action;if(a==="show")showClient(id).catch(err=>show(err.message,"error"));else if(a==="delete")delClient(id).catch(err=>show(err.message,"error"));else act(id,a).catch(err=>show(err.message,"error"))});
    saveBtn.onclick=()=>saveSettings().catch(e=>show(e.message,"error"));bootstrapBtn.onclick=()=>bootstrap().catch(e=>show(e.message,"error"));createBtn.onclick=()=>createClient().catch(e=>show(e.message,"error"));logoutBtn.onclick=()=>logout().catch(e=>show(e.message,"error"));closeDlg.onclick=()=>dlg.close();clientName.addEventListener("keydown",e=>{if(e.key==="Enter")createBtn.click()});load().catch(e=>show(e.message,"error"));
  </script>
</body>
</html>`))

func main() {
	if err := os.MkdirAll(appData, 0700); err != nil {
		log.Fatal(err)
	}
	loginHandler := func(w http.ResponseWriter, r *http.Request) {
		withHeaders(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodGet {
			_ = loginTemplate.Execute(w, nil)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		if !verifyPassword(r.Form.Get("password"), passwordHash) {
			w.WriteHeader(403)
			_ = loginTemplate.Execute(w, map[string]string{"Error": "Неверный пароль"})
			return
		}
		id, csrf := randToken(32), randToken(32)
		sessionsMu.Lock()
		sessions[id] = session{CSRF: csrf, Expires: time.Now().Add(time.Duration(sessionTTL) * time.Second)}
		sessionsMu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "mwg_session", Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: sessionTTL})
		http.Redirect(w, r, "/", http.StatusFound)
	}
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if passwordHash == "" {
			errResp(w, 503, fmt.Errorf("APP_PASSWORD_HASH or APP_PASSWORD is required"))
			return
		}
		if _, _, ok := currentSession(r); !ok {
			loginHandler(w, r)
			return
		}
		withHeaders(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page.Execute(w, nil)
	})
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		id, _, ok := requireAuth(w, r)
		if !ok {
			return
		}
		sessionsMu.Lock()
		delete(sessions, id)
		sessionsMu.Unlock()
		jsonResp(w, map[string]bool{"ok": true})
	})
	http.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) {
		_, s, ok := requireAuth(w, r)
		if !ok {
			return
		}
		jsonResp(w, map[string]string{"csrf": s.CSRF})
	})
	http.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := requireAuth(w, r); !ok {
			return
		}
		st, _ := loadState()
		if r.Method == http.MethodGet {
			jsonResp(w, st.Settings)
			return
		}
		var p Settings
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			errResp(w, 400, err)
			return
		}
		if err := validateSettings(p); err != nil {
			errResp(w, 400, err)
			return
		}
		st.Settings = p
		if err := saveState(st); err != nil {
			errResp(w, 500, err)
			return
		}
		jsonResp(w, st.Settings)
	})
	http.HandleFunc("/api/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := requireAuth(w, r); !ok {
			return
		}
		res, err := bootstrapRouter()
		if err != nil {
			errResp(w, 400, err)
			return
		}
		jsonResp(w, res)
	})
	http.HandleFunc("/api/clients", func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := requireAuth(w, r); !ok {
			return
		}
		st, _ := loadState()
		if r.Method == http.MethodGet {
			jsonResp(w, clientsWithStatus(st.Clients))
			return
		}
		var p struct{ Name string }
		_ = json.NewDecoder(r.Body).Decode(&p)
		c, err := createClient(strings.TrimSpace(p.Name))
		if err != nil {
			errResp(w, 400, err)
			return
		}
		jsonResp(w, c)
	})
	http.HandleFunc("/api/clients/", func(w http.ResponseWriter, r *http.Request) {
		if _, _, ok := requireAuth(w, r); !ok {
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/clients/"), "/")
		if len(parts) < 1 || parts[0] == "" {
			errResp(w, 404, fmt.Errorf("not found"))
			return
		}
		id, action := parts[0], ""
		if len(parts) > 1 {
			action = parts[1]
		}
		st, _ := loadState()
		var c *Client
		for i := range st.Clients {
			if st.Clients[i].ID == id {
				c = &st.Clients[i]
			}
		}
		if c == nil {
			errResp(w, 404, fmt.Errorf("client not found"))
			return
		}
		if r.Method == http.MethodDelete {
			res, err := clientAction(id, "delete")
			if err != nil {
				errResp(w, 400, err)
				return
			}
			jsonResp(w, res)
			return
		}
		switch action {
		case "config":
			if !validClientConfig(c.Config) {
				errResp(w, 409, fmt.Errorf("сохраненная конфигурация клиента невалидна. Нажмите \"Проверить\" или удалите клиента и создайте заново"))
				return
			}
			jsonResp(w, map[string]string{"name": c.Name, "config": c.Config})
		case "download":
			if !validClientConfig(c.Config) {
				errResp(w, 409, fmt.Errorf("сохраненная конфигурация клиента невалидна"))
				return
			}
			w.Header().Set("Content-Disposition", `attachment; filename="`+c.Name+`.conf"`)
			w.Write([]byte(c.Config))
		case "qr":
			if !validClientConfig(c.Config) {
				errResp(w, 409, fmt.Errorf("сохраненная конфигурация клиента невалидна"))
				return
			}
			png, err := qrcode.Encode(c.Config, qrcode.Medium, 256)
			if err != nil {
				errResp(w, 500, err)
				return
			}
			w.Header().Set("Content-Type", "image/png")
			w.Write(png)
		case "disable":
			res, err := clientAction(id, "disable")
			if err != nil {
				errResp(w, 400, err)
				return
			}
			jsonResp(w, res)
		case "enable":
			res, err := clientAction(id, "enable")
			if err != nil {
				errResp(w, 400, err)
				return
			}
			jsonResp(w, res)
		case "recreate-config":
			res, err := clientAction(id, "recreate")
			if err != nil {
				errResp(w, 400, err)
				return
			}
			jsonResp(w, res)
		case "verify":
			res, err := clientAction(id, "verify")
			if err != nil {
				errResp(w, 400, err)
				return
			}
			jsonResp(w, res)
		default:
			errResp(w, 404, fmt.Errorf("not found"))
		}
	})
	log.Printf("listening on %s:%s", appHost, appPort)
	log.Fatal(http.ListenAndServe(appHost+":"+appPort, nil))
}
