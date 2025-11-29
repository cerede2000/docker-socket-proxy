package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
)

// Variables renseignées par -ldflags au build
var (
	version = "dev"
	gitSha  = "unknown"
)

// -----------------------------
// Types de configuration
// -----------------------------

type ServiceConfig struct {
	Name string

	Ping         bool
	Version      bool
	Info         bool
	Events       bool
	Auth         bool
	Build        bool
	Commit       bool
	Configs      bool
	Containers   bool
	Distribution bool
	Exec         bool
	Images       bool
	Networks     bool
	Nodes        bool
	Plugins      bool
	Secrets      bool
	Services     bool
	Session      bool
	Swarm        bool
	System       bool
	Tasks        bool
	Volumes      bool

	Post         bool
	AllowStart   bool
	AllowStop    bool
	AllowRestart bool

	APIRewrite string
}

type ProxyConfig struct {
	Listen           string
	SocketPath       string
	DiscoverInterval time.Duration
	ProfilesFile     string

	baseServices map[string]*ServiceConfig // défini par les args (CLI)
	services     map[string]*ServiceConfig // effectif (CLI + YAML)
	ipToRole     map[string]string         // IP -> nom de rôle

	selfNetworks map[string]struct{} // réseaux du conteneur socket-proxy
}

// -----------------------------
// Structures pour l’API Docker
// -----------------------------

type dockerNetwork struct {
	IPAddress string `json:"IPAddress"`
}

type dockerContainerNetworkBlock struct {
	Networks map[string]dockerNetwork `json:"Networks"`
}

type dockerContainerSummary struct {
	ID              string                      `json:"Id"`
	Names           []string                    `json:"Names"`
	Labels          map[string]string           `json:"Labels"`
	NetworkSettings dockerContainerNetworkBlock `json:"NetworkSettings"`
}

type dockerContainerInspect struct {
	ID              string                      `json:"Id"`
	Name            string                      `json:"Name"`
	NetworkSettings dockerContainerNetworkBlock `json:"NetworkSettings"`
}

// -----------------------------
// Utilitaires généraux
// -----------------------------

func parseBoolString(s string) bool {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return false
	}
}

func normalizeRoleName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(n, "proxy-") {
		n = strings.TrimPrefix(n, "proxy-")
	}
	return n
}

func ensureService(m map[string]*ServiceConfig, role string) *ServiceConfig {
	if s, ok := m[role]; ok {
		return s
	}
	s := &ServiceConfig{Name: role}
	m[role] = s
	return s
}

func anyRightsSet(s *ServiceConfig) bool {
	return s.Ping || s.Version || s.Info || s.Events || s.Auth ||
		s.Build || s.Commit || s.Configs || s.Containers || s.Distribution ||
		s.Exec || s.Images || s.Networks || s.Nodes || s.Plugins ||
		s.Secrets || s.Services || s.Session || s.Swarm ||
		s.System || s.Tasks || s.Volumes
}

func applyDefaultProfileFlags(s *ServiceConfig, role string) {
	if anyRightsSet(s) {
		return
	}
	// Profil par défaut de lecture
	s.Ping = true
	s.Version = true
	s.Info = true
	s.Containers = true
	s.Images = true
	s.Networks = true
}

func applyFlagValue(s *ServiceConfig, flag, value string) {
	// NOTE : pour apirewrite, la logique YAML est gérée dans loadProfilesFromFile.
	// Ici on garde le comportement existant (CLI) inchangé.
	b := parseBoolString(value)
	f := strings.ToLower(strings.TrimSpace(flag))

	switch f {
	case "ping":
		s.Ping = b
	case "version":
		s.Version = b
	case "info":
		s.Info = b
	case "events", "event":
		s.Events = b
	case "auth":
		s.Auth = b
	case "build":
		s.Build = b
	case "commit":
		s.Commit = b
	case "configs":
		s.Configs = b
	case "containers":
		s.Containers = b
	case "distribution":
		s.Distribution = b
	case "exec":
		s.Exec = b
	case "images":
		s.Images = b
	case "networks":
		s.Networks = b
	case "nodes":
		s.Nodes = b
	case "plugins":
		s.Plugins = b
	case "secrets":
		s.Secrets = b
	case "services":
		s.Services = b
	case "session":
		s.Session = b
	case "swarm":
		s.Swarm = b
	case "system":
		s.System = b
	case "tasks":
		s.Tasks = b
	case "volumes":
		s.Volumes = b
	case "post":
		s.Post = b
	case "allow_start":
		s.AllowStart = b
	case "allow_stop":
		s.AllowStop = b
	case "allow_restart", "allow_restarts":
		s.AllowRestart = b
	case "apirewrite":
		// Comportement CLI existant : on se base sur un bool.
		// (YAML ne passe plus par ce chemin pour apirewrite, voir loadProfilesFromFile.)
		if b {
			s.APIRewrite = value
		} else {
			s.APIRewrite = ""
		}
	}
}

func cloneServices(in map[string]*ServiceConfig) map[string]*ServiceConfig {
	out := make(map[string]*ServiceConfig, len(in))
	for k, v := range in {
		c := *v
		out[k] = &c
	}
	return out
}

// -----------------------------
// Parsing configuration
// -----------------------------

func discoverIntervalFromEnv(logger *log.Logger) time.Duration {
	const def = 30 * time.Second
	val := strings.TrimSpace(os.Getenv("DISCOVER_INTERVAL"))
	if val == "" {
		return def
	}
	if d, err := time.ParseDuration(val); err == nil && d > 0 {
		logger.Printf("[config] DISCOVER_INTERVAL=%s", d)
		return d
	}
	if n, err := strconv.Atoi(val); err == nil && n > 0 {
		d := time.Duration(n) * time.Second
		logger.Printf("[config] DISCOVER_INTERVAL=%s", d)
		return d
	}
	logger.Printf("[config] invalid DISCOVER_INTERVAL=%q, using %s", val, def)
	return def
}

func parseConfig(args []string, logger *log.Logger) *ProxyConfig {
	// Fichier de profils par défaut
	profilesPath := strings.TrimSpace(os.Getenv("SOCKETPROXY_PROFILE_FILE"))
	if profilesPath == "" {
		profilesPath = "/config/profiles.yml"
	}

	cfg := &ProxyConfig{
		Listen:           ":2375",
		SocketPath:       "/var/run/docker.sock",
		DiscoverInterval: discoverIntervalFromEnv(logger),
		ProfilesFile:     profilesPath,
		baseServices:     make(map[string]*ServiceConfig),
		services:         make(map[string]*ServiceConfig),
		ipToRole:         make(map[string]string),
		selfNetworks:     make(map[string]struct{}),
	}

	for _, arg := range args {
		if !strings.HasPrefix(arg, "--") {
			continue
		}
		opt := strings.TrimPrefix(arg, "--")

		// Options globales
		if strings.HasPrefix(opt, "listen=") {
			cfg.Listen = strings.TrimPrefix(opt, "listen=")
			continue
		}
		if strings.HasPrefix(opt, "socket=") {
			cfg.SocketPath = strings.TrimPrefix(opt, "socket=")
			continue
		}
		if strings.HasPrefix(opt, "discover-interval=") {
			val := strings.TrimPrefix(opt, "discover-interval=")
			if d, err := time.ParseDuration(val); err == nil && d > 0 {
				cfg.DiscoverInterval = d
			} else if n, err := strconv.Atoi(val); err == nil && n > 0 {
				cfg.DiscoverInterval = time.Duration(n) * time.Second
			}
			continue
		}
		if strings.HasPrefix(opt, "profiles=") {
			cfg.ProfilesFile = strings.TrimPrefix(opt, "profiles=")
			continue
		}

		// Profils / flags :
		// 1) --proxy-home.ping=1
		// 2) --home
		if strings.Contains(opt, ".") {
			parts := strings.SplitN(opt, ".", 2)
			profileKey := parts[0]
			rest := parts[1]

			flagKey := rest
			valStr := "1"
			if strings.Contains(rest, "=") {
				fv := strings.SplitN(rest, "=", 2)
				flagKey = fv[0]
				valStr = fv[1]
			}

			role := normalizeRoleName(profileKey)
			svc := ensureService(cfg.baseServices, role)
			applyFlagValue(svc, flagKey, valStr)
		} else {
			role := normalizeRoleName(opt)
			svc := ensureService(cfg.baseServices, role)
			applyDefaultProfileFlags(svc, role)
		}
	}

	cfg.services = cloneServices(cfg.baseServices)

	logger.Printf("[config] listen=%s socket=%s discover=%s profilesFile=%s",
		cfg.Listen, cfg.SocketPath, cfg.DiscoverInterval, cfg.ProfilesFile)

	if len(cfg.services) == 0 {
		logger.Printf("[config] WARNING: aucun profil défini (pas de --home / --portainer / etc.)")
	} else {
		for name, svc := range cfg.services {
			logger.Printf("[config] profil=%s rights: ping=%v version=%v info=%v containers=%v images=%v networks=%v exec=%v post=%v start=%v stop=%v restart=%v",
				name, svc.Ping, svc.Version, svc.Info, svc.Containers, svc.Images, svc.Networks,
				svc.Exec, svc.Post, svc.AllowStart, svc.AllowStop, svc.AllowRestart)
		}
	}

	return cfg
}

// -----------------------------
// Parser YAML très simple pour profils
// -----------------------------

// On passe de map[string]map[string]bool -> map[string]map[string]string
// pour pouvoir gérer apirewrite: "1.51" en plus des booléens.
func parseProfilesYAML(content string) (map[string]map[string]string, error) {
	profiles := make(map[string]map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(content))
	var current string

	for scanner.Scan() {
		line := scanner.Text()

		// Retirer les commentaires (# ...) et trim
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Nouvelle section : "home:"
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			name := strings.TrimSpace(line)
			name = strings.TrimSuffix(name, ":")
			if name == "" {
				continue
			}
			current = name
			if _, ok := profiles[current]; !ok {
				profiles[current] = make(map[string]string)
			}
			continue
		}

		// Ligne de flag : "  ping: true" ou "  apirewrite: 1.51"
		if current == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			continue
		}
		inner := strings.TrimSpace(line)
		parts := strings.SplitN(inner, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		valStr := strings.TrimSpace(parts[1])
		if key == "" || valStr == "" {
			continue
		}

		// On garde la valeur brute en string. Les bool seront traités plus tard
		// via parseBoolString dans applyFlagValue.
		profiles[current][key] = valStr
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return profiles, nil
}

func loadProfilesFromFile(cfg *ProxyConfig, logger *log.Logger) error {
	if cfg.ProfilesFile == "" {
		return nil
	}

	data, err := os.ReadFile(cfg.ProfilesFile)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Printf("[profiles] file %s not found (skip, will watch for creation)", cfg.ProfilesFile)
			return nil
		}
		return fmt.Errorf("read profiles file: %w", err)
	}

	m, err := parseProfilesYAML(string(data))
	if err != nil {
		// IMPORTANT : on log et on ignore, on ne casse pas le service
		return fmt.Errorf("parse profiles yaml: %w", err)
	}

	newServices := cloneServices(cfg.baseServices)

	for rawName, flags := range m {
		role := normalizeRoleName(rawName)
		s := &ServiceConfig{Name: role}

		for k, v := range flags {
			// apirewrite en YAML : on gère la valeur directement ici
			if strings.EqualFold(k, "apirewrite") {
				val := strings.TrimSpace(v)
				if val == "" || parseBoolString(val) == false && val == "0" {
					// vide / 0 / false -> désactive
					s.APIRewrite = ""
				} else {
					// ex : "1.51"
					s.APIRewrite = val
				}
				continue
			}

			// Pour tous les autres flags, on réutilise la logique existante
			applyFlagValue(s, k, v)
		}

		newServices[role] = s
	}

	cfg.services = newServices

	logger.Printf("[profiles] loaded %d profiles from %s", len(newServices), cfg.ProfilesFile)
	for name, svc := range cfg.services {
		logger.Printf("[profiles] profil=%s ping=%v version=%v info=%v events=%v containers=%v exec=%v post=%v start=%v stop=%v restart=%v apirewrite=%q",
			name, svc.Ping, svc.Version, svc.Info, svc.Events, svc.Containers,
			svc.Exec, svc.Post, svc.AllowStart, svc.AllowStop, svc.AllowRestart, svc.APIRewrite)
	}

	return nil
}

func profileWatcher(ctx context.Context, cfg *ProxyConfig, logger *log.Logger) {
	if cfg.ProfilesFile == "" {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastMod time.Time

	for {
		select {
		case <-ctx.Done():
			logger.Printf("[profiles] watcher stopped")
			return
		case <-ticker.C:
			info, err := os.Stat(cfg.ProfilesFile)
			if err != nil {
				if !os.IsNotExist(err) {
					logger.Printf("[profiles] stat error: %v", err)
				}
				continue
			}
			mt := info.ModTime()
			if mt.After(lastMod) {
				if err := loadProfilesFromFile(cfg, logger); err != nil {
					logger.Printf("[profiles] reload error: %v (keeping previous config)", err)
				} else {
					lastMod = mt
					logger.Printf("[profiles] reloaded after change (%s)", mt)
				}
			}
		}
	}
}

// -----------------------------
// Découverte des conteneurs
// -----------------------------

func newDockerHTTPClient(socketPath string) *http.Client {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	return &http.Client{Transport: tr}
}

func keysOfSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func getSelfNetworks(ctx context.Context, client *http.Client, logger *log.Logger) (map[string]struct{}, error) {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return nil, fmt.Errorf("cannot get hostname: %w", err)
	}

	path := "/containers/" + hostname + "/json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker inspect self: status %d", resp.StatusCode)
	}

	var inspect dockerContainerInspect
	if err := json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		return nil, err
	}

	nets := make(map[string]struct{})
	for name := range inspect.NetworkSettings.Networks {
		nets[name] = struct{}{}
	}
	logger.Printf("[discover] self container=%s networks=%v", hostname, keysOfSet(nets))
	return nets, nil
}

func discoverOnce(ctx context.Context, cfg *ProxyConfig, client *http.Client, logger *log.Logger) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/containers/json?all=0", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker /containers/json status=%d", resp.StatusCode)
	}

	var containers []dockerContainerSummary
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return err
	}

	newMap := make(map[string]string)

	for _, c := range containers {
		if len(c.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(c.Names[0], "/")

		roleLabel := c.Labels["socketproxy.role"]
		if roleLabel == "" {
			roleLabel = c.Labels["socketproxy.service"]
		}
		if roleLabel == "" {
			continue
		}
		role := normalizeRoleName(roleLabel)

		svc := cfg.services[role]
		if svc == nil {
			logger.Printf("[discover] container=%s id=%s role=%s -> no matching profile, skipping",
				name, c.ID[:12], role)
			continue
		}

		var ips []string
		for netName, nw := range c.NetworkSettings.Networks {
			if len(cfg.selfNetworks) > 0 {
				if _, ok := cfg.selfNetworks[netName]; !ok {
					continue
				}
			}
			if nw.IPAddress == "" {
				continue
			}
			ips = append(ips, nw.IPAddress)
			newMap[nw.IPAddress] = role
		}

		if len(ips) > 0 {
			logger.Printf("[discover] container=%s id=%s role=%s ips=%v", name, c.ID[:12], role, ips)
		}
	}

	cfg.ipToRole = newMap
	logger.Printf("[discover] ip→role map size=%d", len(newMap))

	return nil
}

func discoverLoop(ctx context.Context, cfg *ProxyConfig, client *http.Client, logger *log.Logger) {
	ticker := time.NewTicker(cfg.DiscoverInterval)
	defer ticker.Stop()

	for {
		if err := discoverOnce(ctx, cfg, client, logger); err != nil {
			logger.Printf("[discover] error: %v", err)
		}
		select {
		case <-ctx.Done():
			logger.Printf("[discover] loop stopped")
			return
		case <-ticker.C:
		}
	}
}

// -----------------------------
// Classification des paths / droits
// -----------------------------

func trimAPIVersion(path string) string {
	if !strings.HasPrefix(path, "/v") {
		return path
	}
	idx := strings.Index(path[2:], "/")
	if idx == -1 {
		return path
	}
	idx += 2
	ver := path[1:idx]
	if len(ver) < 2 {
		return path
	}
	for i := 1; i < len(ver); i++ {
		c := ver[i]
		if (c < '0' || c > '9') && c != '.' {
			return path
		}
	}
	return path[idx:]
}

func classifyPath(path string) (feature string, action string) {
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}

	p := trimAPIVersion(path)

	if strings.HasPrefix(p, "/engine/api/") {
		p = strings.TrimPrefix(p, "/engine/api")
	}

	switch {
	case p == "/_ping" || strings.HasPrefix(p, "/_ping/"):
		return "ping", ""
	case p == "/version" || strings.HasPrefix(p, "/version/"):
		return "version", ""
	case p == "/info" || strings.HasPrefix(p, "/info/"):
		return "info", ""
	case strings.HasPrefix(p, "/events"):
		return "events", ""
	case strings.HasPrefix(p, "/auth"):
		return "auth", ""
	case strings.HasPrefix(p, "/build"):
		return "build", ""
	case strings.HasPrefix(p, "/commit"):
		return "commit", ""
	case strings.HasPrefix(p, "/configs"):
		return "configs", ""
	case strings.HasPrefix(p, "/containers"):
		segs := strings.Split(strings.Trim(p, "/"), "/")
		if len(segs) >= 3 {
			switch segs[2] {
			case "start":
				return "containers", "start"
			case "stop":
				return "containers", "stop"
			case "restart":
				return "containers", "restart"
			case "exec":
				return "containers", "exec"
			}
		}
		return "containers", ""
	case strings.HasPrefix(p, "/distribution"):
		return "distribution", ""
	case strings.HasPrefix(p, "/exec"):
		return "exec", ""
	case strings.HasPrefix(p, "/images"):
		return "images", ""
	case strings.HasPrefix(p, "/networks"):
		return "networks", ""
	case strings.HasPrefix(p, "/nodes"):
		return "nodes", ""
	case strings.HasPrefix(p, "/plugins"):
		return "plugins", ""
	case strings.HasPrefix(p, "/secrets"):
		return "secrets", ""
	case strings.HasPrefix(p, "/services"):
		return "services", ""
	case strings.HasPrefix(p, "/session"):
		return "session", ""
	case strings.HasPrefix(p, "/swarm"):
		return "swarm", ""
	case strings.HasPrefix(p, "/system"):
		return "system", ""
	case strings.HasPrefix(p, "/tasks"):
		return "tasks", ""
	case strings.HasPrefix(p, "/volumes"):
		return "volumes", ""
	}
	return "unknown", ""
}

func (s *ServiceConfig) Allow(feature, method, action string) bool {
	isWrite := method == http.MethodPost || method == http.MethodPut ||
		method == http.MethodPatch || method == http.MethodDelete

	switch feature {
	case "ping":
		if !s.Ping {
			return false
		}
	case "version":
		if !s.Version {
			return false
		}
	case "info":
		if !s.Info {
			return false
		}
	case "events":
		if !s.Events {
			return false
		}
	case "auth":
		if !s.Auth {
			return false
		}
	case "build":
		if !s.Build {
			return false
		}
	case "commit":
		if !s.Commit {
			return false
		}
	case "configs":
		if !s.Configs {
			return false
		}
	case "containers":
		if !s.Containers {
			return false
		}
	case "distribution":
		if !s.Distribution {
			return false
		}
	case "exec":
		if !s.Exec {
			return false
		}
	case "images":
		if !s.Images {
			return false
		}
	case "networks":
		if !s.Networks {
			return false
		}
	case "nodes":
		if !s.Nodes {
			return false
		}
	case "plugins":
		if !s.Plugins {
			return false
		}
	case "secrets":
		if !s.Secrets {
			return false
		}
	case "services":
		if !s.Services {
			return false
		}
	case "session":
		if !s.Session {
			return false
		}
	case "swarm":
		if !s.Swarm {
			return false
		}
	case "system":
		if !s.System {
			return false
		}
	case "tasks":
		if !s.Tasks {
			return false
		}
	case "volumes":
		if !s.Volumes {
			return false
		}
	default:
		return false
	}

	if !isWrite {
		return true
	}

	if !s.Post {
		return false
	}

	if feature == "containers" {
		switch action {
		case "start":
			return s.AllowStart
		case "stop":
			return s.AllowStop
		case "restart":
			return s.AllowRestart
		}
	}

	return true
}

// -----------------------------
// Handler HTTP / proxy
// -----------------------------

func isLocalIP(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1"
}

func isVersionPath(path string) bool {
	if path == "/version" {
		return true
	}
	return trimAPIVersion(path) == "/version"
}

func proxyHandler(cfg *ProxyConfig, proxy *httputil.ReverseProxy, logger *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		path := r.URL.Path
		method := r.Method

		// Health local : accès direct à /version depuis localhost
		if isLocalIP(host) && isVersionPath(path) {
			logger.Printf("[health] local check ip=%s method=%s path=%s", host, method, path)
			proxy.ServeHTTP(w, r)
			return
		}

		role := cfg.ipToRole[host]
		if role == "" {
			logger.Printf("[deny] ip=%s role=<none> method=%s path=%s", host, method, path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		svc := cfg.services[role]
		if svc == nil {
			logger.Printf("[deny] ip=%s role=%s (unknown) method=%s path=%s", host, role, method, path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		feature, action := classifyPath(path)
		if !svc.Allow(feature, method, action) {
			logger.Printf("[deny] ip=%s role=%s feature=%s action=%s method=%s path=%s",
				host, role, feature, action, method, path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		logger.Printf("[req] ip=%s role=%s feature=%s action=%s method=%s path=%s",
			host, role, feature, action, method, path)

		proxy.ServeHTTP(w, r)
	})
}

// -----------------------------
// Mode healthcheck
// -----------------------------

// -----------------------------
// Mode healthcheck
// -----------------------------

func runHealthcheck() int {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	// 1) Vérifier que le listener HTTP du proxy est up (TCP 127.0.0.1:2375)
	// Possibilité de surcharger via env si besoin :
	//   SOCKETPROXY_HEALTH_LISTEN="127.0.0.1:2376"
	listenAddr := strings.TrimSpace(os.Getenv("SOCKETPROXY_HEALTH_LISTEN"))
	if listenAddr == "" {
		// Valeur par défaut cohérente avec cfg.Listen = ":2375"
		listenAddr = "127.0.0.1:2375"
	}

	logger.Printf("[health] checking HTTP listener on %s", listenAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", listenAddr)
	if err != nil {
		logger.Printf("[health] TCP connect error: %v", err)
		return 1
	}
	_ = conn.Close()

	// 2) Vérifier que le daemon Docker est accessible via le socket Unix
	//   SOCKETPROXY_HEALTH_SOCKET pour override éventuel
	socketPath := strings.TrimSpace(os.Getenv("SOCKETPROXY_HEALTH_SOCKET"))
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	logger.Printf("[health] checking Docker socket at %s", socketPath)

	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/_ping", nil)
	if err != nil {
		logger.Printf("[health] build request error: %v", err)
		return 1
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("[health] request error: %v", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Printf("[health] bad status from Docker /_ping: %d", resp.StatusCode)
		return 1
	}

	logger.Printf("[health] OK")
	return 0
}

// -----------------------------
// main
// -----------------------------

func main() {
	// Mode healthcheck : "docker-socket-proxy healthcheck"
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		code := runHealthcheck()
		os.Exit(code)
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	logger.Printf("[main] starting docker-socket-proxy version=%s git=%s", version, gitSha)

	cfg := parseConfig(os.Args[1:], logger)
	dockerClient := newDockerHTTPClient(cfg.SocketPath)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	nets, err := getSelfNetworks(ctx, dockerClient, logger)
	if err != nil {
		logger.Printf("[discover] WARNING: cannot get self networks: %v (using all networks)", err)
	} else {
		cfg.selfNetworks = nets
	}

	if err := discoverOnce(ctx, cfg, dockerClient, logger); err != nil {
		logger.Printf("[discover] initial error: %v", err)
	}

	if err := loadProfilesFromFile(cfg, logger); err != nil {
		logger.Printf("[profiles] initial load error: %v (using CLI config only)", err)
	}

	go discoverLoop(ctx, cfg, dockerClient, logger)
	go profileWatcher(ctx, cfg, logger)

	targetURL, _ := url.Parse("http://docker")
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = dockerClient.Transport
	proxy.ErrorLog = logger

	handler := proxyHandler(cfg, proxy, logger)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logger.Printf("[main] listening on %s, docker socket=%s, discover every %s, profilesFile=%s",
		cfg.Listen, cfg.SocketPath, cfg.DiscoverInterval, cfg.ProfilesFile)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("http server error: %v", err)
		}
	}()

	<-ctx.Done()
	logger.Printf("[main] shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
