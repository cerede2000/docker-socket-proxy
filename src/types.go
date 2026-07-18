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
