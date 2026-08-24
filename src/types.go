package main

import (
	"strings"
	"sync"
	"time"
)

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
	AllowAll     bool
	AllowArchive bool
	AllowChanges bool
	AllowExport  bool
	AllowInspect bool
	AllowLogs    bool
	AllowPause   bool
	AllowRestart bool
	AllowStart   bool
	AllowStop    bool
	AllowTop     bool
	AllowUnpause bool
	AllowKill    bool

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

	selfNetworks     map[string]struct{}
	selfNetworksHash string

	containerMu     sync.RWMutex
	containersByRef map[string]dockerContainerMeta
	execToContainer map[string]dockerExecCacheEntry
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
	now := time.Now()
	for id, entry := range c.execToContainer {
		if now.After(entry.ExpiresAt) {
			delete(c.execToContainer, id)
		}
	}
	if len(c.execToContainer) >= maxExecCacheEntries {
		var oldestID string
		var oldest time.Time
		for id, entry := range c.execToContainer {
			if oldestID == "" || entry.CreatedAt.Before(oldest) {
				oldestID, oldest = id, entry.CreatedAt
			}
		}
		delete(c.execToContainer, oldestID)
	}
	c.execToContainer[execID] = dockerExecCacheEntry{ContainerID: containerID, CreatedAt: now, ExpiresAt: now.Add(execCacheTTL)}
}

func (c *ProxyConfig) GetExecContainer(execID string) (string, bool) {
	c.containerMu.Lock()
	defer c.containerMu.Unlock()
	entry, ok := c.execToContainer[execID]
	if !ok || time.Now().After(entry.ExpiresAt) {
		delete(c.execToContainer, execID)
		return "", false
	}
	return entry.ContainerID, true
}

const (
	execCacheTTL        = 15 * time.Minute
	maxExecCacheEntries = 4096
)

type dockerExecCacheEntry struct {
	ContainerID string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

func (c *ProxyConfig) updateSelfNetworks(nets map[string]struct{}, hash string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.selfNetworksHash != "" && c.selfNetworksHash == hash {
		return false
	}
	c.selfNetworks = cloneStringSet(nets)
	c.selfNetworksHash = hash
	return true
}

func (c *ProxyConfig) getSelfNetworks() map[string]struct{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneStringSet(c.selfNetworks)
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
}

type dockerContainerMeta struct {
	ID   string
	Name string
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
