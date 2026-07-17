package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
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

	APIRewrite string // Version d'API à forcer (ex: "1.51")

	// ContainerScope contrôle les cibles Docker accessibles par ce profil.
	// "all" conserve le comportement historique, "allowlist" refuse tout nom
	// absent de AllowedContainers et "blacklist" refuse ceux de BlockedContainers.
	ContainerScope    string
	AllowedContainers map[string]struct{}
	BlockedContainers map[string]struct{}
	// ContainerRules ajoute des exceptions nominatives à la portée. Une règle
	// "deny" masque totalement la cible, tandis que "readonly" ne permet que
	// les API de consultation explicitement autorisées.
	ContainerRules map[string]ContainerAccess
}

type ContainerAccess string

const (
	containerAccessFull     ContainerAccess = "full"
	containerAccessReadOnly ContainerAccess = "readonly"
	containerAccessDeny     ContainerAccess = "deny"
)

type ProxyConfig struct {
	Listen           string
	SocketPath       string
	DiscoverInterval time.Duration
	ProfilesFile     string
	DebounceDelay    time.Duration // Délai de debouncing pour les events

	baseServices map[string]*ServiceConfig // défini par les args (CLI)

	// Protection concurrentielle pour les données partagées
	mu       sync.RWMutex
	services map[string]*ServiceConfig // effectif (CLI + YAML)
	ipToRole map[string]string         // IP -> nom de rôle

	selfNetworks     map[string]struct{} // réseaux du conteneur socket-proxy (immuable après init)
	selfNetworksHash string              // hash des réseaux pour cache DNS

	containerMu     sync.RWMutex
	containersByRef map[string]dockerContainerMeta
	execToContainer map[string]string
}

// Getters thread-safe
func (c *ProxyConfig) GetService(role string) *ServiceConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.services[role]
}

func (c *ProxyConfig) GetRole(ip string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ipToRole[ip]
}

func (c *ProxyConfig) GetIPToRoleSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.ipToRole)
}

// Setters thread-safe
func (c *ProxyConfig) SetIPToRole(m map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ipToRole = m
}

func (c *ProxyConfig) SetServices(m map[string]*ServiceConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.services = m
}

func (c *ProxyConfig) SetContainerIndex(m map[string]dockerContainerMeta) {
	c.containerMu.Lock()
	defer c.containerMu.Unlock()
	c.containersByRef = m
}

func (c *ProxyConfig) GetContainer(ref string) (dockerContainerMeta, bool) {
	c.containerMu.RLock()
	defer c.containerMu.RUnlock()
	v, ok := c.containersByRef[normalizeContainerRef(ref)]
	return v, ok
}

func (c *ProxyConfig) UpsertContainer(meta dockerContainerMeta) {
	c.containerMu.Lock()
	defer c.containerMu.Unlock()
	next := make(map[string]dockerContainerMeta, len(c.containersByRef)+3)
	for k, v := range c.containersByRef {
		next[k] = v
	}
	for _, ref := range meta.refs() {
		next[ref] = meta
	}
	c.containersByRef = next
}

func (c *ProxyConfig) SetExecContainer(execID, containerID string) {
	c.containerMu.Lock()
	defer c.containerMu.Unlock()
	c.execToContainer[execID] = containerID
}

func (c *ProxyConfig) GetExecContainer(execID string) (string, bool) {
	c.containerMu.RLock()
	defer c.containerMu.RUnlock()
	containerID, ok := c.execToContainer[execID]
	return containerID, ok
}

// -----------------------------
// Structures pour l'API Docker
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
	State           string                      `json:"State"`
	NetworkSettings dockerContainerNetworkBlock `json:"NetworkSettings"`
}

type dockerContainerInspect struct {
	ID              string                      `json:"Id"`
	Name            string                      `json:"Name"`
	NetworkSettings dockerContainerNetworkBlock `json:"NetworkSettings"`
	Config          struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

type dockerContainerMeta struct {
	ID     string
	Name   string
	Labels map[string]string
}

func normalizeContainerRef(ref string) string {
	return strings.TrimPrefix(strings.TrimSpace(ref), "/")
}

func (m dockerContainerMeta) refs() []string {
	refs := []string{normalizeContainerRef(m.ID), normalizeContainerRef(m.Name)}
	if len(m.ID) >= 12 {
		refs = append(refs, m.ID[:12])
	}
	return refs
}

type dockerExecInspect struct {
	ContainerID string `json:"ContainerID"`
}

// Événement Docker pour /events
type dockerEvent struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
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
	s := &ServiceConfig{
		Name:              role,
		ContainerScope:    "all",
		AllowedContainers: make(map[string]struct{}),
		BlockedContainers: make(map[string]struct{}),
		ContainerRules:    make(map[string]ContainerAccess),
	}
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
	// AUCUN DROIT PAR DÉFAUT
	// Les droits doivent être explicitement définis dans profiles.yml ou via CLI
	// Principe du moindre privilège : deny by default
	return
}

func applyFlagValue(s *ServiceConfig, flag, value string) {
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
		// Pour apirewrite, on prend la valeur brute (ex: "1.51")
		s.APIRewrite = strings.TrimSpace(value)
	case "container_scope":
		s.ContainerScope = strings.ToLower(strings.TrimSpace(value))
	case "allowed_containers", "allowed_container":
		for _, name := range strings.Split(value, ",") {
			if name = normalizeContainerRef(name); name != "" {
				if s.AllowedContainers == nil {
					s.AllowedContainers = make(map[string]struct{})
				}
				s.AllowedContainers[name] = struct{}{}
			}
		}
	case "blocked_containers", "blocked_container":
		for _, name := range strings.Split(value, ",") {
			if name = normalizeContainerRef(name); name != "" {
				if s.BlockedContainers == nil {
					s.BlockedContainers = make(map[string]struct{})
				}
				s.BlockedContainers[name] = struct{}{}
			}
		}
	case "container_rule":
		parts := strings.SplitN(value, ":", 2)
		if len(parts) != 2 {
			return
		}
		name := normalizeContainerRef(parts[0])
		access := ContainerAccess(strings.ToLower(strings.TrimSpace(parts[1])))
		if name == "" || (access != containerAccessDeny && access != containerAccessReadOnly) {
			return
		}
		if s.ContainerRules == nil {
			s.ContainerRules = make(map[string]ContainerAccess)
		}
		s.ContainerRules[name] = access
	}
}

func cloneServices(in map[string]*ServiceConfig) map[string]*ServiceConfig {
	out := make(map[string]*ServiceConfig, len(in))
	for k, v := range in {
		c := *v
		c.AllowedContainers = cloneStringSet(v.AllowedContainers)
		c.BlockedContainers = cloneStringSet(v.BlockedContainers)
		c.ContainerRules = cloneContainerRules(v.ContainerRules)
		out[k] = &c
	}
	return out
}

func cloneStringSet(in map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for key := range in {
		out[key] = struct{}{}
	}
	return out
}

func cloneContainerRules(in map[string]ContainerAccess) map[string]ContainerAccess {
	out := make(map[string]ContainerAccess, len(in))
	for name, access := range in {
		out[name] = access
	}
	return out
}

func (s *ServiceConfig) HasContainerScope() bool {
	return (strings.ToLower(s.ContainerScope) != "" && strings.ToLower(s.ContainerScope) != "all") || len(s.ContainerRules) > 0
}

func (s *ServiceConfig) ContainerAccess(meta dockerContainerMeta) ContainerAccess {
	name := normalizeContainerRef(meta.Name)
	if name == "" {
		return containerAccessDeny
	}
	if access, ok := s.ContainerRules[name]; ok {
		return access
	}
	if _, blocked := s.BlockedContainers[name]; blocked {
		return containerAccessDeny
	}
	switch strings.ToLower(s.ContainerScope) {
	case "", "all":
		return containerAccessFull
	case "allowlist":
		_, allowed := s.AllowedContainers[name]
		if allowed {
			return containerAccessFull
		}
		return containerAccessDeny
	case "blacklist":
		return containerAccessFull
	default:
		return containerAccessDeny
	}
}

func (s *ServiceConfig) AllowsContainer(meta dockerContainerMeta) bool {
	return s.ContainerAccess(meta) != containerAccessDeny
}

func validateContainerScope(s *ServiceConfig) error {
	mode := strings.ToLower(strings.TrimSpace(s.ContainerScope))
	if mode == "" {
		mode = "all"
		s.ContainerScope = mode
	}
	switch mode {
	case "all":
		if len(s.AllowedContainers) > 0 || len(s.BlockedContainers) > 0 {
			return fmt.Errorf("container_scope=all cannot define allowed_containers or blocked_containers")
		}
	case "allowlist":
		if len(s.BlockedContainers) > 0 {
			return fmt.Errorf("container_scope=allowlist cannot define blocked_containers")
		}
	case "blacklist":
		if len(s.AllowedContainers) > 0 {
			return fmt.Errorf("container_scope=blacklist cannot define allowed_containers")
		}
	default:
		return fmt.Errorf("invalid container_scope=%q (expected all, allowlist or blacklist)", s.ContainerScope)
	}
	for name, access := range s.ContainerRules {
		if normalizeContainerRef(name) == "" {
			return fmt.Errorf("container_rules contains an empty name")
		}
		if access != containerAccessDeny && access != containerAccessReadOnly {
			return fmt.Errorf("container_rules[%q] has invalid access %q (expected deny or readonly)", name, access)
		}
		if _, blocked := s.BlockedContainers[name]; blocked {
			return fmt.Errorf("container %q cannot be both blocked_containers and container_rules", name)
		}
	}
	return nil
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

func debounceDelayFromEnv(logger *log.Logger) time.Duration {
	const def = 100 * time.Millisecond // Réduit à 100ms pour meilleure réactivité
	val := strings.TrimSpace(os.Getenv("EVENT_DEBOUNCE_DELAY"))
	if val == "" {
		return def
	}
	if d, err := time.ParseDuration(val); err == nil && d >= 0 {
		logger.Printf("[config] EVENT_DEBOUNCE_DELAY=%s", d)
		return d
	}
	if n, err := strconv.Atoi(val); err == nil && n >= 0 {
		d := time.Duration(n) * time.Millisecond
		logger.Printf("[config] EVENT_DEBOUNCE_DELAY=%s", d)
		return d
	}
	logger.Printf("[config] invalid EVENT_DEBOUNCE_DELAY=%q, using %s", val, def)
	return def
}

func parseConfig(args []string, logger *log.Logger) *ProxyConfig {
	// Fichier de profils par défaut
	profilesPath := strings.TrimSpace(os.Getenv("SOCKETPROXY_PROFILE_FILE"))
	if profilesPath == "" {
		profilesPath = "/config/profiles.yml"
	}

	listen := ":2375"
	if port := strings.TrimSpace(os.Getenv("PROXY_PORT")); port != "" {
		if n, err := strconv.Atoi(port); err == nil && n > 0 && n <= 65535 {
			listen = ":" + port
		} else {
			logger.Printf("[config] invalid PROXY_PORT=%q, using 2375", port)
		}
	}
	if envListen := strings.TrimSpace(os.Getenv("PROXY_LISTEN")); envListen != "" {
		listen = envListen
	}

	socketPath := strings.TrimSpace(os.Getenv("DOCKER_SOCKET_PATH"))
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	cfg := &ProxyConfig{
		Listen:           listen,
		SocketPath:       socketPath,
		DiscoverInterval: discoverIntervalFromEnv(logger),
		DebounceDelay:    debounceDelayFromEnv(logger),
		ProfilesFile:     profilesPath,
		baseServices:     make(map[string]*ServiceConfig),
		services:         make(map[string]*ServiceConfig),
		ipToRole:         make(map[string]string),
		selfNetworks:     make(map[string]struct{}),
		containersByRef:  make(map[string]dockerContainerMeta),
		execToContainer:  make(map[string]string),
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
		if strings.HasPrefix(opt, "debounce-delay=") {
			val := strings.TrimPrefix(opt, "debounce-delay=")
			if d, err := time.ParseDuration(val); err == nil && d >= 0 {
				cfg.DebounceDelay = d
			} else if n, err := strconv.Atoi(val); err == nil && n >= 0 {
				cfg.DebounceDelay = time.Duration(n) * time.Millisecond
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
	for name, svc := range cfg.services {
		if err := validateContainerScope(svc); err != nil {
			logger.Printf("[config] profile=%s invalid container scope: %v; denying all container targets", name, err)
			svc.ContainerScope = "allowlist"
			svc.AllowedContainers = make(map[string]struct{})
			svc.BlockedContainers = make(map[string]struct{})
			svc.ContainerRules = make(map[string]ContainerAccess)
		}
	}

	logger.Printf("[config] listen=%s socket=%s discover=%s debounce=%s profilesFile=%s",
		cfg.Listen, cfg.SocketPath, cfg.DiscoverInterval, cfg.DebounceDelay, cfg.ProfilesFile)

	if len(cfg.services) == 0 {
		logger.Printf("[config] WARNING: aucun profil défini (pas de --home / --portainer / etc.)")
	} else {
		for name, svc := range cfg.services {
			logger.Printf("[config] profil=%s rights: ping=%v version=%v info=%v containers=%v images=%v networks=%v exec=%v post=%v start=%v stop=%v restart=%v scope=%s rules=%d apirewrite=%q",
				name, svc.Ping, svc.Version, svc.Info, svc.Containers, svc.Images, svc.Networks,
				svc.Exec, svc.Post, svc.AllowStart, svc.AllowStop, svc.AllowRestart, svc.ContainerScope, len(svc.ContainerRules), svc.APIRewrite)
		}
	}

	return cfg
}

// -----------------------------
// Parser YAML des profils
// -----------------------------

var knownProfileKeys = map[string]struct{}{
	"ping": {}, "version": {}, "info": {}, "events": {}, "event": {}, "auth": {},
	"build": {}, "commit": {}, "configs": {}, "containers": {}, "distribution": {},
	"exec": {}, "images": {}, "networks": {}, "nodes": {}, "plugins": {}, "secrets": {},
	"services": {}, "session": {}, "swarm": {}, "system": {}, "tasks": {}, "volumes": {},
	"post": {}, "allow_start": {}, "allow_stop": {}, "allow_restart": {}, "allow_restarts": {},
	"apirewrite": {}, "container_scope": {}, "allowed_containers": {}, "blocked_containers": {}, "container_rules": {},
}

func parseProfilesYAML(content string) (map[string]*ServiceConfig, error) {
	var raw map[string]map[string]any
	if err := yaml.Unmarshal([]byte(content), &raw); err != nil {
		return nil, err
	}

	profiles := make(map[string]*ServiceConfig, len(raw))
	for rawName, values := range raw {
		role := normalizeRoleName(rawName)
		if role == "" {
			return nil, fmt.Errorf("empty profile name")
		}
		svc := ensureService(profiles, role)
		for key, value := range values {
			if _, known := knownProfileKeys[key]; !known {
				return nil, fmt.Errorf("profile %q: unknown key %q", role, key)
			}
			switch key {
			case "allowed_containers", "blocked_containers":
				items, ok := value.([]any)
				if !ok {
					return nil, fmt.Errorf("profile %q: %s must be a YAML list", role, key)
				}
				for _, item := range items {
					name, ok := item.(string)
					if !ok || normalizeContainerRef(name) == "" {
						return nil, fmt.Errorf("profile %q: %s must contain non-empty names", role, key)
					}
					applyFlagValue(svc, key, name)
				}
			case "container_rules":
				items, ok := value.([]any)
				if !ok {
					return nil, fmt.Errorf("profile %q: container_rules must be a YAML list", role)
				}
				for _, item := range items {
					rule, ok := item.(map[string]any)
					if !ok || len(rule) != 2 {
						return nil, fmt.Errorf("profile %q: each container_rules entry must contain name and access", role)
					}
					nameValue, hasName := rule["name"]
					accessValue, hasAccess := rule["access"]
					name, nameOK := nameValue.(string)
					access, accessOK := accessValue.(string)
					if !hasName || !hasAccess || !nameOK || !accessOK || normalizeContainerRef(name) == "" {
						return nil, fmt.Errorf("profile %q: each container_rules entry must contain string name and access", role)
					}
					normalizedName := normalizeContainerRef(name)
					normalizedAccess := ContainerAccess(strings.ToLower(strings.TrimSpace(access)))
					if normalizedAccess != containerAccessDeny && normalizedAccess != containerAccessReadOnly {
						return nil, fmt.Errorf("profile %q: invalid container rule for %q (access must be deny or readonly)", role, name)
					}
					if _, exists := svc.ContainerRules[normalizedName]; exists {
						return nil, fmt.Errorf("profile %q: duplicate container rule for %q", role, name)
					}
					svc.ContainerRules[normalizedName] = normalizedAccess
				}
			default:
				switch typed := value.(type) {
				case bool, string, int, int64, float64:
					applyFlagValue(svc, key, fmt.Sprint(typed))
				default:
					return nil, fmt.Errorf("profile %q: %s must be a scalar", role, key)
				}
			}
		}
		if err := validateContainerScope(svc); err != nil {
			return nil, fmt.Errorf("profile %q: %w", role, err)
		}
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
		return fmt.Errorf("parse profiles yaml: %w", err)
	}

	newServices := cloneServices(cfg.baseServices)

	for role, svc := range m {
		newServices[role] = svc
	}

	cfg.SetServices(newServices)

	logger.Printf("[profiles] loaded %d profiles from %s", len(newServices), cfg.ProfilesFile)
	for name, svc := range newServices {
		logger.Printf("[profiles] profil=%s ping=%v version=%v info=%v events=%v containers=%v exec=%v post=%v start=%v stop=%v restart=%v scope=%s allowed=%d blocked=%d rules=%d apirewrite=%q",
			name, svc.Ping, svc.Version, svc.Info, svc.Events, svc.Containers,
			svc.Exec, svc.Post, svc.AllowStart, svc.AllowStop, svc.AllowRestart, svc.ContainerScope, len(svc.AllowedContainers), len(svc.BlockedContainers), len(svc.ContainerRules), svc.APIRewrite)
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
		MaxIdleConns:       10,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: false,
		DisableKeepAlives:  false,
		// Pas de ResponseHeaderTimeout pour supporter /events
		ResponseHeaderTimeout: 0,
	}
	return &http.Client{
		Transport: tr,
		// Timeout à 0 pour supporter les connexions longues (/events)
		Timeout: 0,
	}
}

// newDockerHTTPClientWithTimeout crée un client avec timeout pour les opérations normales
func newDockerHTTPClientWithTimeout(socketPath string) *http.Client {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    false,
		DisableKeepAlives:     false,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}
}

func keysOfSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// hashNetworks génère un hash simple des noms de réseaux pour le cache DNS
func hashNetworks(nets map[string]struct{}) string {
	if len(nets) == 0 {
		return ""
	}
	keys := keysOfSet(nets)
	// Tri pour avoir un hash stable
	for i := 0; i < len(keys)-1; i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return strings.Join(keys, ",")
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

// getSelfNetworksWithCache utilise un cache DNS basé sur le hash des réseaux
func getSelfNetworksWithCache(ctx context.Context, cfg *ProxyConfig, client *http.Client, logger *log.Logger) error {
	nets, err := getSelfNetworks(ctx, client, logger)
	if err != nil {
		return err
	}

	newHash := hashNetworks(nets)

	// Si le hash n'a pas changé, on garde le cache
	if cfg.selfNetworksHash != "" && cfg.selfNetworksHash == newHash {
		logger.Printf("[discover] self networks unchanged (cache hit)")
		return nil
	}

	// Mise à jour du cache
	cfg.selfNetworks = nets
	cfg.selfNetworksHash = newHash
	logger.Printf("[discover] self networks updated (cache miss)")

	return nil
}

func indexContainerSummary(c dockerContainerSummary) dockerContainerMeta {
	name := ""
	if len(c.Names) > 0 {
		name = normalizeContainerRef(c.Names[0])
	}
	return dockerContainerMeta{ID: c.ID, Name: name, Labels: c.Labels}
}

func buildContainerIndex(containers []dockerContainerSummary) map[string]dockerContainerMeta {
	index := make(map[string]dockerContainerMeta, len(containers)*3)
	for _, container := range containers {
		meta := indexContainerSummary(container)
		if meta.ID == "" || meta.Name == "" {
			continue
		}
		for _, ref := range meta.refs() {
			index[ref] = meta
		}
	}
	return index
}

func discoverOnce(ctx context.Context, cfg *ProxyConfig, client *http.Client, logger *log.Logger) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/containers/json?all=1", nil)
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
	newIndex := buildContainerIndex(containers)

	for _, c := range containers {
		if c.State != "running" {
			continue
		}
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

		svc := cfg.GetService(role)
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

	cfg.SetIPToRole(newMap)
	cfg.SetContainerIndex(newIndex)
	logger.Printf("[discover] ip→role map size=%d", cfg.GetIPToRoleSize())

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
// Boucle d'écoute des events Docker avec debouncing intelligent
// -----------------------------

func shouldTriggerDiscover(ev dockerEvent) bool {
	// Événements de type container
	if ev.Type == "container" {
		// Les healthchecks et commandes internes génèrent des exec_* très fréquents
		if strings.HasPrefix(ev.Action, "exec_") {
			return false
		}

		// Les changements de statut de santé ne changent pas l'IP/role
		if strings.HasPrefix(ev.Action, "health_status") {
			return false
		}

		switch ev.Action {
		case "start", "stop", "die", "destroy", "update", "create", "rename", "pause", "unpause":
			return true
		}
	}

	// Événements de type network - gestion des connexions/déconnexions réseau
	if ev.Type == "network" {
		switch ev.Action {
		case "connect", "disconnect":
			// Pour les événements réseau, on vérifie si un container est concerné
			if ev.Actor.Attributes != nil {
				if _, hasContainer := ev.Actor.Attributes["container"]; hasContainer {
					return true
				}
			}
		}
	}

	return false
}

func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

// eventDebouncer gère le debouncing intelligent des événements Docker
// Mode 1 : Premier événement ou isolé (>2x delay) → Trigger immédiat
// Mode 2 : Rafale d'événements → Debouncing actif
// Mode 3 : Délai = 0 → Toujours immédiat (pas de debouncing)
type eventDebouncer struct {
	mu            sync.Mutex
	timer         *time.Timer
	pendingEvents int
	lastTrigger   time.Time
	delay         time.Duration
	callback      func()
}

func newEventDebouncer(delay time.Duration, callback func()) *eventDebouncer {
	return &eventDebouncer{
		delay:    delay,
		callback: callback,
	}
}

func (d *eventDebouncer) trigger() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.pendingEvents++

	// Mode 3 : Si le delay est 0, on déclenche toujours immédiatement (pas de debouncing)
	if d.delay == 0 {
		d.lastTrigger = time.Now()
		count := d.pendingEvents
		d.pendingEvents = 0

		d.mu.Unlock()
		if count > 0 {
			d.callback()
		}
		d.mu.Lock()
		return
	}

	// Mode 1 : Si c'est le premier événement ou si le dernier trigger date de plus de 2x le delay,
	// on déclenche immédiatement pour éviter les latences
	timeSinceLastTrigger := time.Since(d.lastTrigger)
	if d.lastTrigger.IsZero() || timeSinceLastTrigger > d.delay*2 {
		// Déclencher immédiatement
		d.lastTrigger = time.Now()
		count := d.pendingEvents
		d.pendingEvents = 0

		// Unlock avant d'appeler le callback
		d.mu.Unlock()
		if count > 0 {
			d.callback()
		}
		d.mu.Lock()
		return
	}

	// Mode 2 : Rafale d'événements - utiliser le debouncing normal
	if d.timer != nil {
		d.timer.Stop()
	}

	d.timer = time.AfterFunc(d.delay, func() {
		d.mu.Lock()
		count := d.pendingEvents
		d.pendingEvents = 0
		d.lastTrigger = time.Now()
		d.mu.Unlock()

		if count > 0 {
			d.callback()
		}
	})
}

func (d *eventDebouncer) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
	}
}

func (d *eventDebouncer) getPendingCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pendingEvents
}

func (d *eventDebouncer) willTriggerImmediately() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.delay == 0 {
		return true
	}
	timeSinceLastTrigger := time.Since(d.lastTrigger)
	return d.lastTrigger.IsZero() || timeSinceLastTrigger > d.delay*2
}

func eventLoop(ctx context.Context, cfg *ProxyConfig, client *http.Client, logger *log.Logger) {
	backoff := 2 * time.Second
	maxBackoff := 30 * time.Second

	// Créer le debouncer avec callback de découverte
	debouncer := newEventDebouncer(cfg.DebounceDelay, func() {
		if err := discoverOnce(ctx, cfg, client, logger); err != nil {
			logger.Printf("[events] discover error: %v", err)
		}
	})
	defer debouncer.stop()

	for {
		select {
		case <-ctx.Done():
			logger.Printf("[events] loop stopped (context done)")
			return
		default:
		}

		// On écoute les events container ET network
		filterJSON := `{
		  "type":["container","network"],
		  "event":["create","start","stop","die","destroy","update","rename","connect","disconnect"]
		}`
		eventsURL := "http://unix/events?filters=" + url.QueryEscape(filterJSON)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, eventsURL, nil)
		if err != nil {
			logger.Printf("[events] build request error: %v", err)
			time.Sleep(backoff)
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				logger.Printf("[events] request aborted (context done): %v", err)
				return
			}
			logger.Printf("[events] request error: %v (retrying in %s)", err, backoff)
			time.Sleep(backoff)
			// Augmenter le backoff jusqu'à maxBackoff
			backoff = backoff * 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		if resp.StatusCode != http.StatusOK {
			logger.Printf("[events] bad status: %d (retrying in %s)", resp.StatusCode, backoff)
			resp.Body.Close()
			time.Sleep(backoff)
			backoff = backoff * 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// Réinitialiser le backoff en cas de connexion réussie
		backoff = 2 * time.Second
		logger.Printf("[events] connected to /events stream")

		dec := json.NewDecoder(resp.Body)

		for {
			var ev dockerEvent
			if err := dec.Decode(&ev); err != nil {
				if err == io.EOF {
					logger.Printf("[events] EOF on events stream")
				} else {
					if ctx.Err() != nil {
						logger.Printf("[events] decode stopped due to context: %v", err)
					} else {
						logger.Printf("[events] decode error: %v", err)
					}
				}
				break
			}

			if !shouldTriggerDiscover(ev) {
				continue
			}

			// Logging optimisé
			var logDetails string
			if ev.Type == "network" {
				containerID := ""
				networkName := ""
				if ev.Actor.Attributes != nil {
					if cid, ok := ev.Actor.Attributes["container"]; ok {
						containerID = shortID(cid)
					}
					if nname, ok := ev.Actor.Attributes["name"]; ok {
						networkName = nname
					}
				}
				logDetails = fmt.Sprintf("type=network action=%s network=%s container=%s",
					ev.Action, networkName, containerID)
			} else {
				logDetails = fmt.Sprintf("type=container id=%s action=%s",
					shortID(ev.Actor.ID), ev.Action)
			}

			// Déclencher le debouncer avec logging approprié
			willTriggerImmediately := debouncer.willTriggerImmediately()

			if willTriggerImmediately {
				logger.Printf("[events] %s -> triggering discovery immediately", logDetails)
			} else {
				logger.Printf("[events] %s -> debouncing discovery (pending=%d, delay=%s)",
					logDetails, debouncer.getPendingCount()+1, cfg.DebounceDelay)
			}

			debouncer.trigger()
		}

		resp.Body.Close()

		select {
		case <-ctx.Done():
			logger.Printf("[events] loop stopped after stream close")
			return
		case <-time.After(backoff):
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
	isRead := method == http.MethodGet || method == http.MethodHead
	isWrite := method == http.MethodPost || method == http.MethodPut ||
		method == http.MethodPatch || method == http.MethodDelete
	if !isRead && !isWrite {
		return false
	}

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
// Portée des conteneurs
// -----------------------------

type responseFilterKind string

const (
	filterContainerList responseFilterKind = "container-list"
	filterEvents        responseFilterKind = "events"
)

type responseFilterContext struct {
	service *ServiceConfig
	kind    responseFilterKind
}

type responseFilterContextKey struct{}

func (c *ProxyConfig) containerMetas() []dockerContainerMeta {
	c.containerMu.RLock()
	defer c.containerMu.RUnlock()
	seen := make(map[string]struct{})
	metas := make([]dockerContainerMeta, 0, len(c.containersByRef)/2)
	for _, meta := range c.containersByRef {
		if _, ok := seen[meta.ID]; ok {
			continue
		}
		seen[meta.ID] = struct{}{}
		metas = append(metas, meta)
	}
	return metas
}

func (c *ProxyConfig) allowedContainerIDs(service *ServiceConfig) []string {
	ids := make([]string, 0)
	for _, meta := range c.containerMetas() {
		if service.AllowsContainer(meta) {
			ids = append(ids, meta.ID)
		}
	}
	return ids
}

func resolveContainer(ctx context.Context, cfg *ProxyConfig, client *http.Client, ref string) (dockerContainerMeta, error) {
	if meta, ok := cfg.GetContainer(ref); ok {
		return meta, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/containers/"+url.PathEscape(normalizeContainerRef(ref))+"/json", nil)
	if err != nil {
		return dockerContainerMeta{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return dockerContainerMeta{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return dockerContainerMeta{}, fmt.Errorf("docker inspect container %q: status %d", ref, resp.StatusCode)
	}
	var inspect dockerContainerInspect
	if err := json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		return dockerContainerMeta{}, err
	}
	meta := dockerContainerMeta{ID: inspect.ID, Name: normalizeContainerRef(inspect.Name), Labels: inspect.Config.Labels}
	if meta.ID == "" || meta.Name == "" {
		return dockerContainerMeta{}, fmt.Errorf("docker inspect container %q returned incomplete metadata", ref)
	}
	cfg.UpsertContainer(meta)
	return meta, nil
}

func resolveExecContainer(ctx context.Context, cfg *ProxyConfig, client *http.Client, execID string) (dockerContainerMeta, error) {
	if containerID, ok := cfg.GetExecContainer(execID); ok {
		return resolveContainer(ctx, cfg, client, containerID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/exec/"+url.PathEscape(execID)+"/json", nil)
	if err != nil {
		return dockerContainerMeta{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return dockerContainerMeta{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return dockerContainerMeta{}, fmt.Errorf("docker inspect exec %q: status %d", execID, resp.StatusCode)
	}
	var inspect dockerExecInspect
	if err := json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		return dockerContainerMeta{}, err
	}
	if inspect.ContainerID == "" {
		return dockerContainerMeta{}, fmt.Errorf("docker inspect exec %q returned no container ID", execID)
	}
	cfg.SetExecContainer(execID, inspect.ContainerID)
	return resolveContainer(ctx, cfg, client, inspect.ContainerID)
}

func pathWithoutAPIVersion(path string) string {
	p := trimAPIVersion(path)
	if strings.HasPrefix(p, "/engine/api/") {
		return strings.TrimPrefix(p, "/engine/api")
	}
	return p
}

func directContainerReference(path string) (string, bool) {
	parts := strings.Split(strings.Trim(pathWithoutAPIVersion(path), "/"), "/")
	if len(parts) < 2 || parts[0] != "containers" {
		return "", false
	}
	switch parts[1] {
	case "json", "create", "prune":
		return "", false
	default:
		return parts[1], true
	}
}

func rewriteContainerReference(path, containerID string) string {
	parts := strings.Split(path, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "containers" {
			parts[i+1] = containerID
			return strings.Join(parts, "/")
		}
	}
	return path
}

func execReference(path string) (string, bool) {
	parts := strings.Split(strings.Trim(pathWithoutAPIVersion(path), "/"), "/")
	if len(parts) < 2 || parts[0] != "exec" || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func isContainerList(path string) bool {
	return pathWithoutAPIVersion(path) == "/containers/json"
}

func isContainerGlobalOperation(path string) bool {
	p := pathWithoutAPIVersion(path)
	return p == "/containers/create" || p == "/containers/prune"
}

func networkBodyContainerReference(r *http.Request) (string, error) {
	const maxBodySize = 1 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) > maxBodySize {
		return "", fmt.Errorf("network request body exceeds %d bytes", maxBodySize)
	}
	var payload struct {
		Container string `json:"Container"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", err
	}
	if payload.Container == "" {
		return "", fmt.Errorf("network request has no Container field")
	}
	return payload.Container, nil
}

func isNetworkContainerOperation(path string) bool {
	p := pathWithoutAPIVersion(path)
	return strings.HasSuffix(p, "/connect") || strings.HasSuffix(p, "/disconnect")
}

func authorizeContainer(ctx context.Context, cfg *ProxyConfig, client *http.Client, service *ServiceConfig, ref string) (dockerContainerMeta, ContainerAccess, error) {
	meta, err := resolveContainer(ctx, cfg, client, ref)
	if err != nil {
		return dockerContainerMeta{}, containerAccessDeny, err
	}
	access := service.ContainerAccess(meta)
	if access == containerAccessDeny {
		return dockerContainerMeta{}, access, fmt.Errorf("container %q is outside profile scope", meta.Name)
	}
	return meta, access, nil
}

func isReadOnlyContainerRequest(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	parts := strings.Split(strings.Trim(pathWithoutAPIVersion(r.URL.Path), "/"), "/")
	if len(parts) != 3 || parts[0] != "containers" || parts[1] == "" {
		return false
	}
	switch parts[2] {
	case "json", "logs", "stats", "top", "changes":
		return true
	default:
		return false
	}
}

func requireWritableContainer(access ContainerAccess, meta dockerContainerMeta) error {
	if access == containerAccessReadOnly {
		return fmt.Errorf("container %q is read-only for this profile", meta.Name)
	}
	return nil
}

func enforceContainerScope(ctx context.Context, cfg *ProxyConfig, client *http.Client, service *ServiceConfig, feature string, r *http.Request) (*responseFilterContext, error) {
	if !service.HasContainerScope() {
		return nil, nil
	}

	switch feature {
	case "containers":
		if ref, ok := directContainerReference(r.URL.Path); ok {
			meta, access, err := authorizeContainer(ctx, cfg, client, service, ref)
			if err != nil {
				return nil, err
			}
			if access == containerAccessReadOnly && !isReadOnlyContainerRequest(r) {
				return nil, fmt.Errorf("container %q only permits read-only API requests", meta.Name)
			}
			r.URL.Path = rewriteContainerReference(r.URL.Path, meta.ID)
			return nil, nil
		}
		if isContainerList(r.URL.Path) && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			return &responseFilterContext{service: service, kind: filterContainerList}, nil
		}
		if isContainerGlobalOperation(r.URL.Path) {
			return nil, fmt.Errorf("global container operation is denied for scoped profiles")
		}
		return nil, fmt.Errorf("container operation has no enforceable target")
	case "exec":
		ref, ok := execReference(r.URL.Path)
		if !ok {
			return nil, fmt.Errorf("exec operation has no enforceable target")
		}
		meta, err := resolveExecContainer(ctx, cfg, client, ref)
		if err != nil {
			return nil, err
		}
		if service.ContainerAccess(meta) == containerAccessDeny {
			return nil, fmt.Errorf("container %q is outside profile scope", meta.Name)
		}
		if err := requireWritableContainer(service.ContainerAccess(meta), meta); err != nil {
			return nil, err
		}
	case "events":
		return &responseFilterContext{service: service, kind: filterEvents}, nil
	case "networks":
		if r.Method == http.MethodPost && isNetworkContainerOperation(r.URL.Path) {
			ref, err := networkBodyContainerReference(r)
			if err != nil {
				return nil, err
			}
			meta, access, err := authorizeContainer(ctx, cfg, client, service, ref)
			if err != nil {
				return nil, err
			}
			if err := requireWritableContainer(access, meta); err != nil {
				return nil, err
			}
		}
	case "commit":
		if ref := r.URL.Query().Get("container"); ref != "" {
			meta, access, err := authorizeContainer(ctx, cfg, client, service, ref)
			if err != nil {
				return nil, err
			}
			if err := requireWritableContainer(access, meta); err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

func filterContainerListResponse(resp *http.Response, cfg *ProxyConfig, service *ServiceConfig) {
	originalBody := resp.Body
	reader, writer := io.Pipe()
	resp.Body = reader
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")

	go func() {
		defer originalBody.Close()
		defer writer.Close()
		decoder := json.NewDecoder(originalBody)
		if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
			_ = writer.CloseWithError(fmt.Errorf("decode Docker container list: %w", err))
			return
		}
		if _, err := writer.Write([]byte("[")); err != nil {
			return
		}
		first := true
		for decoder.More() {
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				_ = writer.CloseWithError(fmt.Errorf("decode Docker container entry: %w", err))
				return
			}
			var container dockerContainerSummary
			if err := json.Unmarshal(raw, &container); err != nil {
				_ = writer.CloseWithError(fmt.Errorf("decode Docker container entry: %w", err))
				return
			}
			meta := indexContainerSummary(container)
			if !service.AllowsContainer(meta) {
				continue
			}
			if !first {
				if _, err := writer.Write([]byte(",")); err != nil {
					return
				}
			}
			first = false
			if _, err := writer.Write(raw); err != nil {
				return
			}
		}
		if _, err := decoder.Token(); err != nil {
			_ = writer.CloseWithError(fmt.Errorf("close Docker container list: %w", err))
			return
		}
		_, _ = writer.Write([]byte("]"))
	}()
}

func filterEventsResponse(resp *http.Response, cfg *ProxyConfig, service *ServiceConfig) {
	originalBody := resp.Body
	reader, writer := io.Pipe()
	resp.Body = reader
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")

	go func() {
		defer originalBody.Close()
		defer writer.Close()
		decoder := json.NewDecoder(originalBody)
		for {
			var raw json.RawMessage
			if err := decoder.Decode(&raw); err != nil {
				if err != io.EOF {
					_ = writer.CloseWithError(fmt.Errorf("decode Docker event: %w", err))
				}
				return
			}
			var event dockerEvent
			if err := json.Unmarshal(raw, &event); err != nil {
				_ = writer.CloseWithError(fmt.Errorf("decode Docker event: %w", err))
				return
			}
			if event.Type != "container" {
				continue
			}
			meta, ok := cfg.GetContainer(event.Actor.ID)
			if !ok || !service.AllowsContainer(meta) {
				continue
			}
			if _, err := writer.Write(raw); err != nil {
				return
			}
			if _, err := writer.Write([]byte("\n")); err != nil {
				return
			}
		}
	}()
}

func scopeResponseFilter(cfg *ProxyConfig) func(*http.Response) error {
	return func(resp *http.Response) error {
		filter, _ := resp.Request.Context().Value(responseFilterContextKey{}).(*responseFilterContext)
		if filter == nil || resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return nil
		}
		switch filter.kind {
		case filterContainerList:
			filterContainerListResponse(resp, cfg, filter.service)
		case filterEvents:
			filterEventsResponse(resp, cfg, filter.service)
		}
		return nil
	}
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

// rewriteAPIVersion remplace la version d'API dans le path par la version cible
// Exemples:
//   - /containers/json -> /v1.51/containers/json
//   - /v1.40/containers/json -> /v1.51/containers/json
//   - /v1.43/images/json -> /v1.51/images/json
func rewriteAPIVersion(path, targetVersion string) string {
	if targetVersion == "" {
		return path
	}

	// Si le path ne commence pas par /v, on ajoute la version
	if !strings.HasPrefix(path, "/v") {
		return "/v" + targetVersion + path
	}

	// Si le path commence par /v, on remplace la version existante
	// Format: /v1.XX/reste
	idx := strings.Index(path[2:], "/")
	if idx == -1 {
		// Un endpoint tel que /version commence par "/v" sans être un préfixe
		// d'API. Dans ce cas, il faut ajouter la version comme pour tout autre
		// endpoint non versionné.
		versionPart := path[2:]
		for _, c := range versionPart {
			if (c < '0' || c > '9') && c != '.' {
				return "/v" + targetVersion + path
			}
		}
		return path
	}

	// Vérifier que c'est bien une version (v + chiffres + points)
	versionPart := path[2 : idx+2]
	for _, c := range versionPart {
		if (c < '0' || c > '9') && c != '.' {
			// Ce n'est pas une version valide, on ne modifie pas
			return path
		}
	}

	// Remplacer la version
	return "/v" + targetVersion + path[idx+2:]
}

func proxyHandler(cfg *ProxyConfig, resolverClient *http.Client, proxy *httputil.ReverseProxy, logger *log.Logger) http.Handler {
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

		role := cfg.GetRole(host)
		if role == "" {
			logger.Printf("[deny] ip=%s role=<none> method=%s path=%s", host, method, path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		svc := cfg.GetService(role)
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

		responseFilter, err := enforceContainerScope(r.Context(), cfg, resolverClient, svc, feature, r)
		if err != nil {
			logger.Printf("[deny] ip=%s role=%s feature=%s method=%s path=%s scope=%s reason=%v",
				host, role, feature, method, path, svc.ContainerScope, err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if responseFilter != nil {
			r = r.WithContext(context.WithValue(r.Context(), responseFilterContextKey{}, responseFilter))
		}

		// Réécriture de la version d'API si configurée
		originalPath := r.URL.Path
		if svc.APIRewrite != "" {
			r.URL.Path = rewriteAPIVersion(r.URL.Path, svc.APIRewrite)
			if r.URL.Path != originalPath {
				logger.Printf("[req] ip=%s role=%s feature=%s action=%s method=%s path=%s -> rewritten to=%s (api=%s)",
					host, role, feature, action, method, originalPath, r.URL.Path, svc.APIRewrite)
			} else {
				logger.Printf("[req] ip=%s role=%s feature=%s action=%s method=%s path=%s (api=%s)",
					host, role, feature, action, method, path, svc.APIRewrite)
			}
		} else {
			logger.Printf("[req] ip=%s role=%s feature=%s action=%s method=%s path=%s",
				host, role, feature, action, method, path)
		}

		proxy.ServeHTTP(w, r)
	})
}

// -----------------------------
// Mode healthcheck
// -----------------------------

func runHealthcheck() int {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	port := strings.TrimSpace(os.Getenv("PROXY_PORT"))
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		port = "2375"
	}
	healthURL := "http://127.0.0.1:" + port + "/version"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		logger.Printf("[health] build request error: %v", err)
		return 1
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Printf("[health] request error: %v", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Printf("[health] bad status: %d", resp.StatusCode)
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Client pour le proxy (sans timeout pour supporter /events)
	proxyClient := newDockerHTTPClient(cfg.SocketPath)

	// Client avec timeout pour les opérations de découverte
	discoveryClient := newDockerHTTPClientWithTimeout(cfg.SocketPath)

	// Chargement initial des profiles AVANT tout
	if err := loadProfilesFromFile(cfg, logger); err != nil {
		logger.Printf("[profiles] initial load error: %v (using CLI config only)", err)
	}

	// Initialisation du cache DNS pour les réseaux
	if err := getSelfNetworksWithCache(ctx, cfg, discoveryClient, logger); err != nil {
		logger.Printf("[discover] WARNING: cannot get self networks: %v (using all networks)", err)
	}

	// CRITIQUE : Découverte initiale SYNCHRONE - DOIT réussir avant de démarrer le serveur
	// Sinon Traefik (qui démarre en même temps) reçoit 403 Forbidden
	logger.Printf("[main] performing initial discovery (synchronous)...")
	maxRetries := 5
	retryDelay := 1 * time.Second
	discoverySuccess := false

	for i := 0; i < maxRetries; i++ {
		if err := discoverOnce(ctx, cfg, discoveryClient, logger); err != nil {
			logger.Printf("[discover] initial discovery attempt %d/%d failed: %v", i+1, maxRetries, err)
			if i < maxRetries-1 {
				time.Sleep(retryDelay)
				retryDelay = retryDelay * 2 // Backoff
			}
		} else {
			discoverySuccess = true
			logger.Printf("[main] initial discovery successful - found %d containers", cfg.GetIPToRoleSize())
			break
		}
	}

	if !discoverySuccess {
		logger.Printf("[main] WARNING: initial discovery failed after %d attempts - starting anyway", maxRetries)
	}

	// Boucles de fond :
	// - découverte périodique (avec timeout)
	// - watcher du fichier de profiles
	// - écoute des events Docker (update au fil de l'eau avec debouncing intelligent, avec timeout)
	go discoverLoop(ctx, cfg, discoveryClient, logger)
	go profileWatcher(ctx, cfg, logger)
	go eventLoop(ctx, cfg, discoveryClient, logger)

	targetURL, _ := url.Parse("http://docker")
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	// Utiliser le client SANS timeout pour le proxy (support /events)
	proxy.Transport = proxyClient.Transport
	proxy.ErrorLog = logger
	proxy.ModifyResponse = scopeResponseFilter(cfg)

	handler := proxyHandler(cfg, discoveryClient, proxy, logger)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// WriteTimeout doit être 0 pour supporter les connexions longues comme /events
		// Traefik et autres clients maintiennent /events ouvert indéfiniment
		WriteTimeout:   0,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	logger.Printf("[main] listening on %s, docker socket=%s, discover every %s, debounce=%s, profilesFile=%s",
		cfg.Listen, cfg.SocketPath, cfg.DiscoverInterval, cfg.DebounceDelay, cfg.ProfilesFile)

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
