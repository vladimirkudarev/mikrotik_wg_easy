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
	"io"
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
	if err != nil {
		return "", fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
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
	if out, err := runRouterOS(fmt.Sprintf("/interface/wireguard/peers/print as-value where interface=%s", rosQuote(st.Settings.WGInterface))); err == nil {
		for _, field := range strings.Fields(out) {
			if strings.HasPrefix(field, "allowed-address=") || strings.HasPrefix(field, "client-address=") {
				for _, addr := range strings.Split(strings.SplitN(field, "=", 2)[1], ",") {
					used[strings.Trim(addr, `"`)] = true
				}
			}
		}
	}
	for candidate := append(net.IP(nil), netw.IP...); netw.Contains(candidate); incIP(candidate) {
		if candidate.Equal(netw.IP) || candidate.Equal(routerIP) {
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
	cfg, err := runRouterOS(fmt.Sprintf(`:put [/interface/wireguard/peers/show-client-config [find where comment=%s]]`, rosQuote(comment)))
	if err != nil {
		return Client{}, err
	}
	c := Client{ID: id, Name: name, Address: addr, Comment: comment, Config: cfg, CreatedAt: time.Now().Format(time.RFC3339)}
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
			if _, err := runRouterOS(fmt.Sprintf(`/interface/wireguard/peers/remove %s`, find)); err != nil {
				return nil, err
			}
			st.Clients = append(st.Clients[:i], st.Clients[i+1:]...)
			return map[string]bool{"ok": true}, saveState(st)
		case "recreate":
			cfg, err := runRouterOS(fmt.Sprintf(`:put [/interface/wireguard/peers/show-client-config %s]`, find))
			if err != nil {
				return nil, err
			}
			st.Clients[i].Config = cfg
			return map[string]string{"name": c.Name, "config": cfg}, saveState(st)
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

var page = template.Must(template.New("page").Parse(`<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MikroTik WireGuard Easy</title><style>body{font-family:system-ui;margin:0;background:#f6f7f8;color:#1d252c}main{max-width:1120px;margin:0 auto;padding:28px}header{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:20px}section{background:white;border:1px solid #dde2e7;border-radius:8px;padding:16px;margin-bottom:16px}input{box-sizing:border-box;width:100%;padding:9px;border:1px solid #c9d1d9;border-radius:6px}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}button{border:0;border-radius:6px;background:#135cc8;color:white;padding:9px 12px;cursor:pointer}.secondary{background:#eef2f7;color:#1d252c;border:1px solid #ccd4dd}table{width:100%;border-collapse:collapse}td,th{text-align:left;border-bottom:1px solid #e5e9ee;padding:9px}pre{white-space:pre-wrap;background:#111827;color:#fff;border-radius:8px;padding:12px;overflow:auto}.actions{display:flex;gap:8px;flex-wrap:wrap}</style></head><body><main><header><h1>MikroTik WireGuard Easy</h1><div class="actions"><button onclick="bootstrap()">Применить настройку</button><button class="secondary" onclick="logout()">Выйти</button></div></header><section><h2>Настройки</h2><div class="grid" id="settings"></div><p><button class="secondary" onclick="saveSettings()">Сохранить</button></p></section><section><h2>Клиенты</h2><p><input id="clientName" placeholder="Имя клиента"><button onclick="createClient()">Создать клиента</button></p><table><thead><tr><th>Имя</th><th>Адрес</th><th>Статус</th><th></th></tr></thead><tbody id="clients"></tbody></table></section><dialog id="dlg"><h2 id="title"></h2><img id="qr"><pre id="config"></pre><button onclick="dlg.close()">Закрыть</button></dialog></main><script>let csrf="";const fields=["router_host","router_user","router_port","ssh_key","wg_interface","listen_port","client_cidr","router_address","endpoint","dns","allowed_ips","keepalive","wan_interface_list"];function esc(v){return String(v||"").replaceAll("&","&amp;").replaceAll('"',"&quot;").replaceAll("<","&lt;")}async function api(p,o={}){let h={"content-type":"application/json",...(o.headers||{})};if(o.method&&o.method!="GET")h["x-csrf-token"]=csrf;let r=await fetch(p,{...o,headers:h});let t=await r.text();let d;try{d=t?JSON.parse(t):null}catch{d=t}if(!r.ok)throw new Error(d?.error||t);return d}async function load(){csrf=(await api("/api/session")).csrf;let s=await api("/api/settings");settings.innerHTML=fields.map(k=>'<div><label>'+k+'</label><input id="s_'+k+'" value="'+esc(s[k])+'"></div>').join("");let rows=await api("/api/clients");clients.innerHTML=rows.map(c=>'<tr><td>'+esc(c.name)+'</td><td>'+esc(c.address)+'</td><td>'+(c.disabled?"Отключен":"Активен")+'</td><td class="actions"><button class="secondary" onclick="showClient(\\''+c.id+'\\')">QR/Config</button><a href="/api/clients/'+c.id+'/download">.conf</a><button class="secondary" onclick="act(\\''+c.id+'\\',\\''+(c.disabled?"enable":"disable")+'\\')">'+(c.disabled?"Включить":"Отключить")+'</button><button class="secondary" onclick="act(\\''+c.id+'\\',\\'recreate-config\\')">Пересоздать</button><button class="secondary" onclick="del(\\''+c.id+'\\')">Удалить</button></td></tr>').join("")}async function saveSettings(){let p={};fields.forEach(k=>p[k]=document.getElementById("s_"+k).value);await api("/api/settings",{method:"POST",body:JSON.stringify(p)});await load()}async function bootstrap(){await saveSettings();alert(JSON.stringify(await api("/api/bootstrap",{method:"POST",body:"{}"})))}async function createClient(){let name=clientName.value.trim();if(!name)return;let c=await api("/api/clients",{method:"POST",body:JSON.stringify({name})});clientName.value="";await load();await showClient(c.id)}async function showClient(id){let c=await api("/api/clients/"+id+"/config");title.textContent=c.name;config.textContent=c.config;qr.src="/api/clients/"+id+"/qr";dlg.showModal()}async function act(id,a){let r=await api("/api/clients/"+id+"/"+a,{method:"POST",body:"{}"});await load();if(r.config){title.textContent=r.name;config.textContent=r.config;qr.src="/api/clients/"+id+"/qr";dlg.showModal()}}async function del(id){if(confirm("Удалить клиента?")){await api("/api/clients/"+id,{method:"DELETE",body:"{}"});await load()}}async function logout(){await api("/logout",{method:"POST",body:"{}"});location.href="/login"}load().catch(e=>alert(e.message));</script></body></html>`))

func main() {
	if err := os.MkdirAll(appData, 0700); err != nil {
		log.Fatal(err)
	}
	loginHandler := func(w http.ResponseWriter, r *http.Request) {
		withHeaders(w)
		if r.Method == http.MethodGet {
			io.WriteString(w, `<form method="post" action="/"><input name="password" type="password" autofocus><button>Login</button></form>`)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		if !verifyPassword(r.Form.Get("password"), passwordHash) {
			w.WriteHeader(403)
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
			jsonResp(w, st.Clients)
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
			jsonResp(w, map[string]string{"name": c.Name, "config": c.Config})
		case "download":
			w.Header().Set("Content-Disposition", `attachment; filename="`+c.Name+`.conf"`)
			w.Write([]byte(c.Config))
		case "qr":
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
		default:
			errResp(w, 404, fmt.Errorf("not found"))
		}
	})
	log.Printf("listening on %s:%s", appHost, appPort)
	log.Fatal(http.ListenAndServe(appHost+":"+appPort, nil))
}
