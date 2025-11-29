package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Ces variables peuvent être surchargées via -ldflags
var (
	version = "dev"
	gitSha  = "unknown"
)

// ---------------------------------------------------------
// Types de configuration
// ---------------------------------------------------------

type ServiceConfig struct {
	// Nom de profil logique, ex: "home", "portainer"
	Name string

	// Permissions Docker API
	AllowPing         bool
	AllowVersion      bool
	AllowInfo         bool
	AllowEvents       bool
	AllowAuth         bool
	AllowBuild        bool
	AllowCommit       bool
	AllowConfigs      bool
	AllowContainers   bool
	AllowDistribution bool
	AllowExec         bool
	AllowImages       bool
	AllowNetworks     bool
	AllowNodes        bool
	AllowPlugins      bool
	AllowSecrets      bool
	AllowServices     bool
	AllowSession      bool
	AllowSwarm        bool
	AllowSystem       bool
	AllowTasks        bool
	AllowVolumes      bool

	// Écriture
	AllowPost    bool
	AllowStart   bool
	AllowStop    bool
	AllowRestart bool

	// Rewrite éventuelle de l’API Docker (/vX.Y/ -> /vAPIVERSION/)
	APIVersionOverride string
}

type ProxyConfig struct {
	ListenAddr string
	SocketPath string

	// clé = profil logique ("home", "watchtower", "portainer"...)
	Services map[string]*ServiceConfig
}

// Index IP → profil de service
type ClientIndex struct {
	mu        sync.RWMutex
	ipToSvc   map[string]string // "10.248.15.3" -> "home"
	lastBuild time.Time
}

func (ci *ClientIndex) Get(ip string) (string, bool) {
	ci.mu.RLock()
	defer ci.mu.RUnlock()
	svc, ok := ci.ipToSvc[ip]
	return svc, ok
}

func (ci *ClientIndex) Replace(newMap map[string]string) {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	ci.ipToSvc = newMap
	ci.lastBuild = time.Now()
}

// ---------------------------------------------------------
// Structures Docker pour la découverte
// ---------------------------------------------------------

type dockerContainerListItem struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Labels map[string]string `json:"Labels"`
}

type dockerContainerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// ---------------------------------------------------------
// Proxy state
// ---------------------------------------------------------

type ProxyState struct {
	cfg             *ProxyConfig
	dockerClient    *http.Client
	reverseProxy    *httputil.ReverseProxy
	clients         *ClientIndex
	allowedNetworks map[string]struct{} // réseaux du socket-proxy lui-même
}

// ---------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseBool(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func normalizeIPv4(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func shortID(id string) string {
	if len(id) >= 12 {
		return id[:12]
	}
	return id
}

// ---------------------------------------------------------
// Parsing des arguments --<profil>.<flag>=<val>
// (ex: --home.ping=1, --proxy-home.containers=1)
// ---------------------------------------------------------

func parseConfigFromArgs() *ProxyConfig {
	cfg := &ProxyConfig{
		ListenAddr: envOrDefault("LISTEN_ADDR", ":2375"),
		SocketPath: envOrDefault("DOCKER_SOCKET_PATH", "/var/run/docker.sock"),
		Services:   make(map[string]*ServiceConfig),
	}

	for _, arg := range os.Args[1:] {
		// Params globaux
		if strings.HasPrefix(arg, "--listen=") {
			cfg.ListenAddr = strings.TrimPrefix(arg, "--listen=")
			continue
		}
		if strings.HasPrefix(arg, "--socket-path=") {
			cfg.SocketPath = strings.TrimPrefix(arg, "--socket-path=")
			continue
		}

		if !strings.HasPrefix(arg, "--") {
			continue
		}

		trim := strings.TrimPrefix(arg, "--")
		nameVal := strings.SplitN(trim, "=", 2)
		key := nameVal[0] // ex: "home.containers" ou "proxy-home.containers"
		val := "1"
		if len(nameVal) == 2 {
			val = nameVal[1]
		}

		// On ne prend que les clés du type "<profil>.<flag>"
		if !strings.Contains(key, ".") {
			continue
		}

		parts := strings.SplitN(key, ".", 2)
		svcKey := parts[0]  // "home" ou "proxy-home"
		flagName := parts[1] // "containers"

		// Profil logique = svcKey sans le préfixe "proxy-" s'il existe
		profile := strings.TrimPrefix(svcKey, "proxy-")
		if profile == "" {
			continue
		}

		flagKey := strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))

		svc := cfg.Services[profile]
		if svc == nil {
			svc = &ServiceConfig{Name: profile}
			cfg.Services[profile] = svc
		}

		switch flagKey {
		case "PING":
			svc.AllowPing = parseBool(val)
		case "VERSION":
			svc.AllowVersion = parseBool(val)
		case "INFO":
			svc.AllowInfo = parseBool(val)
		case "EVENTS", "EVENT":
			svc.AllowEvents = parseBool(val)
		case "AUTH":
			svc.AllowAuth = parseBool(val)
		case "BUILD":
			svc.AllowBuild = parseBool(val)
		case "COMMIT":
			svc.AllowCommit = parseBool(val)
		case "CONFIGS":
			svc.AllowConfigs = parseBool(val)
		case "CONTAINERS":
			svc.AllowContainers = parseBool(val)
		case "DISTRIBUTION":
			svc.AllowDistribution = parseBool(val)
		case "EXEC":
			svc.AllowExec = parseBool(val)
		case "IMAGES":
			svc.AllowImages = parseBool(val)
		case "NETWORKS":
			svc.AllowNetworks = parseBool(val)
		case "NODES":
			svc.AllowNodes = parseBool(val)
		case "PLUGINS":
			svc.AllowPlugins = parseBool(val)
		case "SECRETS":
			svc.AllowSecrets = parseBool(val)
		case "SERVICES":
			svc.AllowServices = parseBool(val)
		case "SESSION":
			svc.AllowSession = parseBool(val)
		case "SWARM":
			svc.AllowSwarm = parseBool(val)
		case "SYSTEM":
			svc.AllowSystem = parseBool(val)
		case "TASKS":
			svc.AllowTasks = parseBool(val)
		case "VOLUMES":
			svc.AllowVolumes = parseBool(val)
		case "POST":
			svc.AllowPost = parseBool(val)
		case "ALLOW_START":
			svc.AllowStart = parseBool(val)
		case "ALLOW_STOP":
			svc.AllowStop = parseBool(val)
		case "ALLOW_RESTARTS", "ALLOW_RESTART":
			svc.AllowRestart = parseBool(val)
		case "APIREWRITE":
			// ex: --portainer.apirewrite=1.51 ou --proxy-portainer.apirewrite=1.51
			svc.APIVersionOverride = strings.TrimSpace(val)
		default:
			log.Printf("[config] Unknown flag for profile %s: %s=%s", profile, flagKey, val)
		}
	}

	log.Printf("[config] listen=%s socket=%s", cfg.ListenAddr, cfg.SocketPath)
	for name, s := range cfg.Services {
		log.Printf("[config] profile=%s (ping=%v version=%v info=%v containers=%v exec=%v images=%v networks=%v post=%v start=%v stop=%v restart=%v apirewrite=%q)",
			name,
			s.AllowPing, s.AllowVersion, s.AllowInfo, s.AllowContainers, s.AllowExec,
			s.AllowImages, s.AllowNetworks,
			s.AllowPost, s.AllowStart, s.AllowStop, s.AllowRestart,
			s.APIVersionOverride,
		)
	}

	return cfg
}

// ---------------------------------------------------------
// Docker client (Unix socket)
// ---------------------------------------------------------

func newDockerHTTPClient(socketPath string) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}
}

// ---------------------------------------------------------
// Découverte des réseaux du socket-proxy lui-même
// ---------------------------------------------------------

func detectSelfContainerCandidates() []string {
	var candidates []string

	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		candidates = append(candidates, strings.TrimSpace(h))
	}

	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			parts := strings.Split(line, ":")
			if len(parts) != 3 {
				continue
			}
			path := parts[2]
			if idx := strings.LastIndex(path, "/"); idx >= 0 && idx+1 < len(path) {
				id := strings.TrimSpace(path[idx+1:])
				if id != "" {
					candidates = append(candidates, id)
				}
			}
		}
	}

	uniq := make(map[string]struct{})
	var out []string
	for _, c := range candidates {
		if _, ok := uniq[c]; !ok {
			uniq[c] = struct{}{}
			out = append(out, c)
		}
	}
	return out
}

func discoverSelfNetworks(ctx context.Context, dockerClient *http.Client) (map[string]struct{}, error) {
	cands := detectSelfContainerCandidates()
	if len(cands) == 0 {
		return nil, errors.New("no self container candidates")
	}

	var lastErr error
	for _, id := range cands {
		urlStr := fmt.Sprintf("http://docker/containers/%s/json", id)
		req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := dockerClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("status=%d body=%s", resp.StatusCode, string(body))
			continue
		}

		var ins dockerContainerInspect
		if err := json.NewDecoder(resp.Body).Decode(&ins); err != nil {
			_ = resp.Body.Close()
			lastErr = err
			continue
		}
		_ = resp.Body.Close()

		nets := make(map[string]struct{})
		for netName := range ins.NetworkSettings.Networks {
			nets[netName] = struct{}{}
		}

		if len(nets) == 0 {
			lastErr = fmt.Errorf("no networks found on self container %s", id)
			continue
		}

		log.Printf("[self] detected container=%s name=%s networks=%v", shortID(ins.ID), ins.Name, keysOfSet(nets))
		return nets, nil
	}

	return nil, fmt.Errorf("discoverSelfNetworks failed, lastErr=%v", lastErr)
}

func keysOfSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------------------------------------------------------
// Découverte des conteneurs avec label socketproxy.service
// ---------------------------------------------------------

func (ps *ProxyState) discoverClients(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://docker/containers/json?all=true", nil)
	if err != nil {
		return err
	}

	resp, err := ps.dockerClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("docker /containers/json status=%d body=%s", resp.StatusCode, string(body))
	}

	var list []dockerContainerListItem
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return fmt.Errorf("decode containers/json: %w", err)
	}

	newMap := make(map[string]string)

	for _, c := range list {
		raw, ok := c.Labels["socketproxy.service"]
		if !ok {
			continue
		}
		svcLabel := strings.TrimSpace(raw)
		if svcLabel == "" {
			continue
		}

		// Normalisation : "proxy-home" -> "home"
		profile := strings.TrimPrefix(svcLabel, "proxy-")
		if profile == "" {
			continue
		}

		if _, exists := ps.cfg.Services[profile]; !exists {
			log.Printf("[discover] container=%s has socketproxy.service=%q (profile=%s) but no matching profile in config; ignoring",
				shortID(c.ID), svcLabel, profile)
			continue
		}

		if err := ps.addIPsFromInspect(ctx, newMap, c.ID, profile); err != nil {
			log.Printf("[discover] inspect error for %s (profile=%s): %v", shortID(c.ID), profile, err)
			continue
		}
	}

	ps.clients.Replace(newMap)
	log.Printf("[discover] index built with %d IP(s)", len(newMap))
	return nil
}

func (ps *ProxyState) addIPsFromInspect(ctx context.Context, ipMap map[string]string, containerID, profile string) error {
	urlStr := fmt.Sprintf("http://docker/containers/%s/json", containerID)
	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return err
	}
	resp, err := ps.dockerClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("inspect status=%d body=%s", resp.StatusCode, string(body))
	}

	var ins dockerContainerInspect
	if err := json.NewDecoder(resp.Body).Decode(&ins); err != nil {
		return fmt.Errorf("decode inspect: %w", err)
	}

	name := strings.TrimPrefix(ins.Name, "/")
	if name == "" && len(ins.Config.Labels["com.docker.compose.service"]) > 0 {
		name = ins.Config.Labels["com.docker.compose.service"]
	}

	for netName, netData := range ins.NetworkSettings.Networks {
		// 🔒 Filtrage : on ne garde que les réseaux du socket-proxy lui-même
		if len(ps.allowedNetworks) > 0 {
			if _, ok := ps.allowedNetworks[netName]; !ok {
				continue
			}
		}

		ip := strings.TrimSpace(netData.IPAddress)
		if ip == "" {
			continue
		}
		normIP := normalizeIPv4(ip)
		ipMap[normIP] = profile
		log.Printf("[discover] profile=%s container=%s network=%s ip=%s",
			profile, name, netName, normIP)
	}

	return nil
}

// ---------------------------------------------------------
// Santé / healthcheck
// ---------------------------------------------------------

func isLocalRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "::ffff:")

	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

func (ps *ProxyState) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://docker/version", nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp, err := ps.dockerClient.Do(req)
	if err != nil {
		http.Error(w, "docker unreachable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "docker /version not OK", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("[health] copy body error: %v", err)
	}
}

// ---------------------------------------------------------
// Classification des paths / ACL
// ---------------------------------------------------------

type endpointGroup string

const (
	groupUnknown      endpointGroup = ""
	groupPing         endpointGroup = "ping"
	groupVersion      endpointGroup = "version"
	groupInfo         endpointGroup = "info"
	groupEvents       endpointGroup = "events"
	groupAuth         endpointGroup = "auth"
	groupBuild        endpointGroup = "build"
	groupCommit       endpointGroup = "commit"
	groupConfigs      endpointGroup = "configs"
	groupContainers   endpointGroup = "containers"
	groupDistribution endpointGroup = "distribution"
	groupExec         endpointGroup = "exec"
	groupImages       endpointGroup = "images"
	groupNetworks     endpointGroup = "networks"
	groupNodes        endpointGroup = "nodes"
	groupPlugins      endpointGroup = "plugins"
	groupSecrets      endpointGroup = "secrets"
	groupServices     endpointGroup = "services"
	groupSession      endpointGroup = "session"
	groupSwarm        endpointGroup = "swarm"
	groupSystem       endpointGroup = "system"
	groupTasks        endpointGroup = "tasks"
	groupVolumes      endpointGroup = "volumes"
)

type pathInfo struct {
	Group     endpointGroup
	IsStart   bool
	IsStop    bool
	IsRestart bool
	IsExec    bool
}

func stripAPIVersion(p string) string {
	if !strings.HasPrefix(p, "/v") {
		return p
	}
	dotSeen := false
	for i := 2; i < len(p); i++ {
		ch := p[i]
		if ch == '/' {
			if dotSeen {
				return p[i:]
			}
			return p
		}
		if ch == '.' {
			dotSeen = true
		} else if ch < '0' || ch > '9' {
			return p
		}
	}
	return p
}

func classifyPath(path string) pathInfo {
	res := pathInfo{Group: groupUnknown}

	trim := stripAPIVersion(path)

	if idx := strings.Index(trim, "?"); idx >= 0 {
		trim = trim[:idx]
	}

	if trim == "/_ping" {
		res.Group = groupPing
		return res
	}
	if trim == "/version" {
		res.Group = groupVersion
		return res
	}
	if trim == "/info" {
		res.Group = groupInfo
		return res
	}

	switch {
	case strings.HasPrefix(trim, "/events"):
		res.Group = groupEvents
	case strings.HasPrefix(trim, "/auth"):
		res.Group = groupAuth
	case strings.HasPrefix(trim, "/build"):
		res.Group = groupBuild
	case strings.HasPrefix(trim, "/commit"):
		res.Group = groupCommit
	case strings.HasPrefix(trim, "/configs"):
		res.Group = groupConfigs
	case strings.HasPrefix(trim, "/containers"):
		res.Group = groupContainers
		if strings.Contains(trim, "/exec") {
			res.Group = groupExec
			res.IsExec = true
		}
		if strings.HasSuffix(trim, "/start") {
			res.IsStart = true
		} else if strings.HasSuffix(trim, "/stop") {
			res.IsStop = true
		} else if strings.HasSuffix(trim, "/restart") {
			res.IsRestart = true
		}
	case strings.HasPrefix(trim, "/distribution"):
		res.Group = groupDistribution
	case strings.HasPrefix(trim, "/exec"):
		res.Group = groupExec
		res.IsExec = true
	case strings.HasPrefix(trim, "/images"):
		res.Group = groupImages
	case strings.HasPrefix(trim, "/networks"):
		res.Group = groupNetworks
	case strings.HasPrefix(trim, "/nodes"):
		res.Group = groupNodes
	case strings.HasPrefix(trim, "/plugins"):
		res.Group = groupPlugins
	case strings.HasPrefix(trim, "/secrets"):
		res.Group = groupSecrets
	case strings.HasPrefix(trim, "/services"):
		res.Group = groupServices
	case strings.HasPrefix(trim, "/session"):
		res.Group = groupSession
	case strings.HasPrefix(trim, "/swarm"):
		res.Group = groupSwarm
	case strings.HasPrefix(trim, "/system"):
		res.Group = groupSystem
	case strings.HasPrefix(trim, "/tasks"):
		res.Group = groupTasks
	case strings.HasPrefix(trim, "/volumes"):
		res.Group = groupVolumes
	default:
		res.Group = groupUnknown
	}

	return res
}

func checkACL(svc *ServiceConfig, pi pathInfo, method string) error {
	isWrite := method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete

	if !isWrite {
		switch pi.Group {
		case groupPing:
			if !svc.AllowPing {
				return errors.New("ping not allowed")
			}
		case groupVersion:
			if !svc.AllowVersion {
				return errors.New("version not allowed")
			}
		case groupInfo:
			if !svc.AllowInfo {
				return errors.New("info not allowed")
			}
		case groupEvents:
			if !svc.AllowEvents {
				return errors.New("events not allowed")
			}
		case groupAuth:
			if !svc.AllowAuth {
				return errors.New("auth not allowed")
			}
		case groupBuild:
			if !svc.AllowBuild {
				return errors.New("build not allowed")
			}
		case groupCommit:
			if !svc.AllowCommit {
				return errors.New("commit not allowed")
			}
		case groupConfigs:
			if !svc.AllowConfigs {
				return errors.New("configs not allowed")
			}
		case groupContainers:
			if !svc.AllowContainers {
				return errors.New("containers not allowed")
			}
		case groupDistribution:
			if !svc.AllowDistribution {
				return errors.New("distribution not allowed")
			}
		case groupExec:
			if !svc.AllowExec {
				return errors.New("exec not allowed")
			}
		case groupImages:
			if !svc.AllowImages {
				return errors.New("images not allowed")
			}
		case groupNetworks:
			if !svc.AllowNetworks {
				return errors.New("networks not allowed")
			}
		case groupNodes:
			if !svc.AllowNodes {
				return errors.New("nodes not allowed")
			}
		case groupPlugins:
			if !svc.AllowPlugins {
				return errors.New("plugins not allowed")
			}
		case groupSecrets:
			if !svc.AllowSecrets {
				return errors.New("secrets not allowed")
			}
		case groupServices:
			if !svc.AllowServices {
				return errors.New("services not allowed")
			}
		case groupSession:
			if !svc.AllowSession {
				return errors.New("session not allowed")
			}
		case groupSwarm:
			if !svc.AllowSwarm {
				return errors.New("swarm not allowed")
			}
		case groupSystem:
			if !svc.AllowSystem {
				return errors.New("system not allowed")
			}
		case groupTasks:
			if !svc.AllowTasks {
				return errors.New("tasks not allowed")
			}
		case groupVolumes:
			if !svc.AllowVolumes {
				return errors.New("volumes not allowed")
			}
		case groupUnknown:
			return errors.New("unknown path group")
		}
		return nil
	}

	if !svc.AllowPost {
		return errors.New("write methods not allowed (POST/PUT/PATCH/DELETE)")
	}

	if pi.IsStart && !svc.AllowStart {
		return errors.New("container start not allowed")
	}
	if pi.IsStop && !svc.AllowStop {
		return errors.New("container stop not allowed")
	}
	if pi.IsRestart && !svc.AllowRestart {
		return errors.New("container restart not allowed")
	}

	switch pi.Group {
	case groupExec:
		if !svc.AllowExec {
			return errors.New("exec write not allowed")
		}
	case groupContainers:
		if !svc.AllowContainers {
			return errors.New("containers write not allowed")
		}
	case groupImages:
		if !svc.AllowImages {
			return errors.New("images write not allowed")
		}
	case groupNetworks:
		if !svc.AllowNetworks {
			return errors.New("networks write not allowed")
		}
	case groupServices:
		if !svc.AllowServices {
			return errors.New("services write not allowed")
		}
	case groupVolumes:
		if !svc.AllowVolumes {
			return errors.New("volumes write not allowed")
		}
	case groupBuild:
		if !svc.AllowBuild {
			return errors.New("build write not allowed")
		}
	case groupConfigs:
		if !svc.AllowConfigs {
			return errors.New("configs write not allowed")
		}
	}

	return nil
}

// ---------------------------------------------------------
// Handler HTTP principal
// ---------------------------------------------------------

func (ps *ProxyState) resolveServiceForIP(ip string) *ServiceConfig {
	if name, ok := ps.clients.Get(ip); ok {
		if svc, ok2 := ps.cfg.Services[name]; ok2 {
			return svc
		}
	}

	log.Printf("[acl] unknown client ip=%s, forcing discovery...", ip)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ps.discoverClients(ctx); err != nil {
		log.Printf("[acl] discovery error while resolving ip=%s: %v", ip, err)
	}

	if name, ok := ps.clients.Get(ip); ok {
		if svc, ok2 := ps.cfg.Services[name]; ok2 {
			return svc
		}
	}

	return nil
}

func rewriteAPIVersionIfNeeded(path string, svc *ServiceConfig) string {
	if svc == nil || svc.APIVersionOverride == "" {
		return path
	}
	if strings.HasPrefix(path, "/v") {
		for i := 2; i < len(path); i++ {
			if path[i] == '/' {
				return "/v" + svc.APIVersionOverride + path[i:]
			}
			if (path[i] < '0' || path[i] > '9') && path[i] != '.' {
				break
			}
		}
	}
	return path
}

func (ps *ProxyState) handler(w http.ResponseWriter, r *http.Request) {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	ip := normalizeIPv4(strings.TrimPrefix(strings.TrimSpace(remoteHost), "::ffff:"))

	// Healthcheck interne
	if r.URL.Path == "/version" && isLocalRemote(r.RemoteAddr) {
		ps.handleHealth(w, r)
		return
	}

	svc := ps.resolveServiceForIP(ip)
	if svc == nil {
		log.Printf("[req] ip=%s svc=? method=%s path=%s -> DENY (no socketproxy.service mapping)", ip, r.Method, r.URL.Path)
		http.Error(w, "Forbidden: no socketproxy.service mapping for this client", http.StatusForbidden)
		return
	}

	log.Printf("[req] ip=%s svc=%s method=%s path=%s", ip, svc.Name, r.Method, r.URL.Path)

	pi := classifyPath(r.URL.Path)
	if err := checkACL(svc, pi, r.Method); err != nil {
		log.Printf("[acl] deny ip=%s svc=%s method=%s path=%s reason=%v", ip, svc.Name, r.Method, r.URL.Path, err)
		http.Error(w, "Forbidden by docker-socket-proxy ACL", http.StatusForbidden)
		return
	}

	origPath := r.URL.Path
	r.URL.Path = rewriteAPIVersionIfNeeded(r.URL.Path, svc)
	if origPath != r.URL.Path {
		log.Printf("[rewrite] svc=%s ip=%s %s -> %s", svc.Name, ip, origPath, r.URL.Path)
	}

	ps.reverseProxy.ServeHTTP(w, r)
}

// ---------------------------------------------------------
// main
// ---------------------------------------------------------

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg := parseConfigFromArgs()

	if len(cfg.Services) == 0 {
		log.Println("[fatal] no <profile> configuration found (no --home.* / --portainer.* / …)")
		os.Exit(1)
	}

	dockerClient := newDockerHTTPClient(cfg.SocketPath)

	// Découvrir les réseaux du container socket-proxy
	var allowedNets map[string]struct{}
	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		nets, err := discoverSelfNetworks(ctx, dockerClient)
		cancel()
		if err != nil {
			log.Printf("[self] WARNING: cannot discover self networks: %v (no network filtering will be applied)", err)
			allowedNets = make(map[string]struct{})
		} else {
			allowedNets = nets
			log.Printf("[self] allowed networks for client IP mapping: %v", keysOfSet(allowedNets))
		}
	}

	targetURL, _ := url.Parse("http://docker")
	rp := httputil.NewSingleHostReverseProxy(targetURL)
	rp.Transport = dockerClient.Transport
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[proxy] error for path=%s: %v", r.URL.Path, err)
		http.Error(w, "Bad gateway (error talking to docker)", http.StatusBadGateway)
	}

	state := &ProxyState{
		cfg:             cfg,
		dockerClient:    dockerClient,
		reverseProxy:    rp,
		clients:         &ClientIndex{ipToSvc: make(map[string]string)},
		allowedNetworks: allowedNets,
	}

	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := state.discoverClients(ctx); err != nil {
			log.Printf("[discover] initial discovery failed: %v", err)
		}
		cancel()
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := state.discoverClients(ctx); err != nil {
				log.Printf("[discover] periodic discovery error: %v", err)
			}
			cancel()
		}
	}()

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      http.HandlerFunc(state.handler),
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 0,
	}

	log.Printf("[startup] docker-socket-proxy (go) version=%s gitSha=%s listening on %s, socket=%s",
		version, gitSha, cfg.ListenAddr, cfg.SocketPath)

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("[fatal] ListenAndServe error: %v", err)
	}
}
