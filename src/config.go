package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

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
