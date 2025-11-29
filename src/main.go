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
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Profile describes the allowed Docker API surface for a logical service.
type Profile struct {
	Name string

	// Read endpoints
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

	// Write behaviour
	Post         bool // allow POST/PUT/PATCH/DELETE on allowed endpoints
	AllowStart   bool
	AllowStop    bool
	AllowRestart bool

	// Optional API version override (e.g. "1.51")
	APIRewrite string
}

// ContainerAccess describes which profile is attached to a given container IP.
type ContainerAccess struct {
	ContainerID string
	Name        string
	ProfileName string
}

// AccessManager holds runtime mapping: IP -> profile, containerID -> IPs.
type AccessManager struct {
	mu      sync.RWMutex
	ipToAcc map[string]ContainerAccess
	idToIPs map[string][]string
}

func NewAccessManager() *AccessManager {
	return &AccessManager{
		ipToAcc: make(map[string]ContainerAccess),
		idToIPs: make(map[string][]string),
	}
}

func (am *AccessManager) UpdateContainer(containerID, name, profileName string, ips []string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Remove old IPs for this container
	if oldIPs, ok := am.idToIPs[containerID]; ok {
		for _, ip := range oldIPs {
			delete(am.ipToAcc, ip)
		}
	}

	// Insert new IPs
	am.idToIPs[containerID] = ips
	for _, ip := range ips {
		am.ipToAcc[ip] = ContainerAccess{
			ContainerID: containerID,
			Name:        name,
			ProfileName: profileName,
		}
	}
}

func (am *AccessManager) RemoveContainer(containerID string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if oldIPs, ok := am.idToIPs[containerID]; ok {
		for _, ip := range oldIPs {
			delete(am.ipToAcc, ip)
		}
		delete(am.idToIPs, containerID)
	}
}

func (am *AccessManager) FindByIP(ip string) (ContainerAccess, bool) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	acc, ok := am.ipToAcc[ip]
	return acc, ok
}

func (am *AccessManager) Stats() (containers int, ips int) {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return len(am.idToIPs), len(am.ipToAcc)
}

// DockerClient is an HTTP client speaking to the Docker Engine via unix socket.
type DockerClient struct {
	httpClient *http.Client
}

func NewDockerClient(socketPath string) *DockerClient {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &DockerClient{
		httpClient: &http.Client{
			Transport: transport,
			// No Timeout here: we control it via contexts per request
		},
	}
}

func (dc *DockerClient) do(ctx context.Context, method, path string, query url.Values, body io.Reader) (*http.Response, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u := &url.URL{
		Scheme:   "http",
		Host:     "docker", // ignored by unix dialer
		Path:     path,
		RawQuery: "",
	}
	if query != nil {
		u.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	return dc.httpClient.Do(req)
}

func (dc *DockerClient) Ping(ctx context.Context) error {
	resp, err := dc.do(ctx, http.MethodGet, "/version", nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker /version returned %s", resp.Status)
	}
	return nil
}

// ContainerListResponse is a minimal view of /containers/json.
type ContainerListResponse struct {
	ID              string            `json:"Id"`
	Names           []string          `json:"Names"`
	Labels          map[string]string `json:"Labels"`
	NetworkSettings *struct {
		Networks map[string]*struct {
			IPAddress         string `json:"IPAddress"`
			GlobalIPv6Address string `json:"GlobalIPv6Address"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

func (dc *DockerClient) ListContainers(ctx context.Context) ([]ContainerListResponse, error) {
	q := url.Values{}
	q.Set("all", "1")
	resp, err := dc.do(ctx, http.MethodGet, "/containers/json", q, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("docker /containers/json: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var out []ContainerListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ContainerInspectResponse is a minimal view of /containers/{id}/json.
type ContainerInspectResponse struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config *struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	NetworkSettings *struct {
		Networks map[string]*struct {
			IPAddress         string `json:"IPAddress"`
			GlobalIPv6Address string `json:"GlobalIPv6Address"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

func (dc *DockerClient) InspectContainer(ctx context.Context, id string) (*ContainerInspectResponse, error) {
	path := "/containers/" + id + "/json"
	resp, err := dc.do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("docker %s: %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	var out ContainerInspectResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DockerEvent represents a single event from /events.
type DockerEvent struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Time     int64 `json:"time"`
	TimeNano int64 `json:"timeNano"`
}

func (dc *DockerClient) Events(ctx context.Context) (io.ReadCloser, error) {
	q := url.Values{}
	// Filter to container events only
	filters := map[string][]string{
		"type": {"container"},
	}
	filterJSON, _ := json.Marshal(filters)
	q.Set("filters", string(filterJSON))

	resp, err := dc.do(ctx, http.MethodGet, "/events", q, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("docker /events: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return resp.Body, nil
}

// parseBool parses various truthy values ("1","true","yes","on").
func parseBool(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

// parseProfilesFromArgs parses CLI args like --proxy-homepage.containers=1.
func parseProfilesFromArgs(args []string) map[string]*Profile {
	profiles := make(map[string]*Profile)
	for _, arg := range args {
		if !strings.HasPrefix(arg, "--proxy-") {
			continue
		}
		trim := strings.TrimPrefix(arg, "--")
		val := ""
		if i := strings.IndexByte(trim, '='); i >= 0 {
			val = trim[i+1:]
			trim = trim[:i]
		} else {
			val = "1"
		}
		parts := strings.SplitN(trim, ".", 2)
		if len(parts) != 2 {
			continue
		}
		profileName := parts[0] // e.g. "proxy-homepage"
		flagName := parts[1]    // e.g. "containers"

		p := profiles[profileName]
		if p == nil {
			p = &Profile{Name: profileName}
			profiles[profileName] = p
		}
		setProfileFlag(p, flagName, val)
	}
	return profiles
}

func setProfileFlag(p *Profile, flagName, value string) {
	key := strings.ToLower(flagName)

	// Special case: API rewrite is a string version like "1.51"
	if key == "apirewrite" || key == "api_rewrite" {
		p.APIRewrite = strings.TrimSpace(value)
		return
	}

	v := parseBool(value)

	switch key {
	case "ping":
		p.Ping = v
	case "version":
		p.Version = v
	case "info":
		p.Info = v
	case "events", "event":
		p.Events = v
	case "auth":
		p.Auth = v
	case "build":
		p.Build = v
	case "commit":
		p.Commit = v
	case "configs":
		p.Configs = v
	case "containers":
		p.Containers = v
	case "distribution":
		p.Distribution = v
	case "exec":
		p.Exec = v
	case "images":
		p.Images = v
	case "networks":
		p.Networks = v
	case "nodes":
		p.Nodes = v
	case "plugins":
		p.Plugins = v
	case "secrets":
		p.Secrets = v
	case "services":
		p.Services = v
	case "session":
		p.Session = v
	case "swarm":
		p.Swarm = v
	case "system":
		p.System = v
	case "tasks":
		p.Tasks = v
	case "volumes":
		p.Volumes = v
	case "post":
		p.Post = v
	case "allow_start":
		p.AllowStart = v
	case "allow_stop":
		p.AllowStop = v
	case "allow_restart", "allow_restarts":
		p.AllowRestart = v
	default:
		// Unknown flag -> ignore
	}
}

// ensureProfileForLabel returns a Profile for a given label, creating a "zero-rights"
// profile if necessary. It also tries mapping "label" -> "proxy-label" if needed.
func ensureProfileForLabel(label string, profiles map[string]*Profile) *Profile {
	if label == "" {
		return nil
	}
	if p, ok := profiles[label]; ok {
		return p
	}
	if p, ok := profiles["proxy-"+label]; ok {
		return p
	}
	// Unknown profile: create one with no rights
	p := &Profile{Name: label}
	profiles[label] = p
	return p
}

// extractIPsFromNetworks returns all non-empty IPv4/IPv6 addresses from docker networks.
func extractIPsFromNetworks(networks map[string]*struct {
	IPAddress         string `json:"IPAddress"`
	GlobalIPv6Address string `json:"GlobalIPv6Address"`
}) []string {
	var ips []string
	for name, n := range networks {
		_ = name // not used, but may be helpful for debug later
		if n == nil {
			continue
		}
		if ip := strings.TrimSpace(n.IPAddress); ip != "" {
			ips = append(ips, ip)
		}
		if ip6 := strings.TrimSpace(n.GlobalIPv6Address); ip6 != "" {
			ips = append(ips, ip6)
		}
	}
	return ips
}

// normalizeRemoteIP converts IPv6-mapped IPv4 (::ffff:a.b.c.d) to plain a.b.c.d.
func normalizeRemoteIP(remote string) string {
	host := remote
	if strings.Contains(remote, ":") {
		// remote is usually "IP:port"
		if h, _, err := net.SplitHostPort(remote); err == nil {
			host = h
		}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// analyzePath decomposes the Docker HTTP path into endpoint, action and version info.
func analyzePath(path string) (endpoint string, action string, hasVersion bool, versionIndex int, segments []string) {
	versionIndex = -1
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return "", "", false, -1, nil
	}
	segments = strings.Split(trimmed, "/")
	mainIdx := 0
	if len(segments) > 1 && strings.HasPrefix(segments[0], "v") {
		hasVersion = true
		versionIndex = 0
		mainIdx = 1
	}
	main := segments[mainIdx]

	// Determine action for some endpoints
	switch main {
	case "containers":
		// pattern: containers/{id}/{action}
		if len(segments) > mainIdx+2 {
			action = segments[mainIdx+2]
		}
	case "exec":
		// pattern: exec/{id}/{action}
		if len(segments) > mainIdx+2 {
			action = segments[mainIdx+2]
		}
	default:
		action = ""
	}

	// Map main to logical endpoint
	switch main {
	case "_ping":
		endpoint = "ping"
	case "version":
		endpoint = "version"
	case "info":
		endpoint = "info"
	case "events":
		endpoint = "events"
	case "auth":
		endpoint = "auth"
	case "build":
		endpoint = "build"
	case "commit":
		endpoint = "commit"
	case "configs":
		endpoint = "configs"
	case "containers":
		endpoint = "containers"
	case "distribution":
		endpoint = "distribution"
	case "exec":
		endpoint = "exec"
	case "images":
		endpoint = "images"
	case "networks":
		endpoint = "networks"
	case "nodes":
		endpoint = "nodes"
	case "plugins":
		endpoint = "plugins"
	case "secrets":
		endpoint = "secrets"
	case "services":
		endpoint = "services"
	case "session":
		endpoint = "session"
	case "swarm":
		endpoint = "swarm"
	case "system":
		endpoint = "system"
	case "tasks":
		endpoint = "tasks"
	case "volumes":
		endpoint = "volumes"
	default:
		endpoint = ""
	}

	return endpoint, action, hasVersion, versionIndex, segments
}

func isMethodSafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// isAllowed checks whether a given profile is allowed to call an endpoint/action with a given method.
func isAllowed(p *Profile, method, endpoint, action string) bool {
	if p == nil {
		return false
	}

	// Determine if endpoint is allowed at all
	allowedRead := false
	switch endpoint {
	case "ping":
		allowedRead = p.Ping
	case "version":
		allowedRead = p.Version
	case "info":
		allowedRead = p.Info
	case "events":
		allowedRead = p.Events
	case "auth":
		allowedRead = p.Auth
	case "build":
		allowedRead = p.Build
	case "commit":
		allowedRead = p.Commit
	case "configs":
		allowedRead = p.Configs
	case "containers":
		allowedRead = p.Containers
	case "distribution":
		allowedRead = p.Distribution
	case "exec":
		allowedRead = p.Exec
	case "images":
		allowedRead = p.Images
	case "networks":
		allowedRead = p.Networks
	case "nodes":
		allowedRead = p.Nodes
	case "plugins":
		allowedRead = p.Plugins
	case "secrets":
		allowedRead = p.Secrets
	case "services":
		allowedRead = p.Services
	case "session":
		allowedRead = p.Session
	case "swarm":
		allowedRead = p.Swarm
	case "system":
		allowedRead = p.System
	case "tasks":
		allowedRead = p.Tasks
	case "volumes":
		allowedRead = p.Volumes
	default:
		allowedRead = false
	}
	if !allowedRead {
		return false
	}

	if isMethodSafe(method) {
		// GET/HEAD/OPTIONS
		return true
	}

	// Write methods: require POST permission
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		if !p.Post {
			return false
		}
	default:
		// Unknown method -> deny
		return false
	}

	// Additional restrictions for some endpoints/actions
	if endpoint == "containers" {
		switch action {
		case "start":
			return p.AllowStart
		case "stop":
			return p.AllowStop
		case "restart":
			return p.AllowRestart
		}
	}

	// For exec and others, Post + endpoint flag is enough
	return true
}

// initialDiscovery scans all containers and fills the AccessManager based on labels.
func initialDiscovery(ctx context.Context, dc *DockerClient, am *AccessManager, profiles map[string]*Profile, labelKey string) error {
	log.Printf("[discover] starting initial discovery")
	containers, err := dc.ListContainers(ctx)
	if err != nil {
		return err
	}
	for _, c := range containers {
		if c.Labels == nil {
			continue
		}
		labelVal := strings.TrimSpace(c.Labels[labelKey])
		if labelVal == "" {
			continue
		}
		profile := ensureProfileForLabel(labelVal, profiles)
		if profile == nil {
			continue
		}
		if c.NetworkSettings == nil || len(c.NetworkSettings.Networks) == 0 {
			continue
		}
		ips := extractIPsFromNetworks(c.NetworkSettings.Networks)
		if len(ips) == 0 {
			continue
		}
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		shortID := c.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		am.UpdateContainer(c.ID, name, profile.Name, ips)
		log.Printf("[discover] container=%s id=%s profile=%s ips=%v", name, shortID, profile.Name, ips)
	}
	containersCount, ipsCount := am.Stats()
	log.Printf("[discover] completed: containers=%d ips=%d", containersCount, ipsCount)
	return nil
}

// watchEvents keeps the AccessManager in sync with Docker container events.
func watchEvents(ctx context.Context, dc *DockerClient, am *AccessManager, profiles map[string]*Profile, labelKey string) {
	backoff := time.Second

	for {
		select {
		case <-ctx.Done():
			log.Printf("[events] context cancelled, stopping events watcher")
			return
		default:
		}

		log.Printf("[events] connecting to Docker /events")
		body, err := dc.Events(ctx)
		if err != nil {
			log.Printf("[events] error opening events stream: %v", err)
			time.Sleep(backoff)
			continue
		}

		dec := json.NewDecoder(body)
		for {
			var evt DockerEvent
			if err := dec.Decode(&evt); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
					log.Printf("[events] stream ended: %v", err)
					break
				}
				log.Printf("[events] decode error: %v", err)
				break
			}

			if evt.Type != "container" {
				continue
			}

			containerID := evt.Actor.ID
			action := evt.Action

			switch action {
			case "start":
				// Inspect container and (re)register IPs
				go func(id string) {
					ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					ins, err := dc.InspectContainer(ctx2, id)
					if err != nil {
						log.Printf("[events] inspect error for %s: %v", id, err)
						return
					}
					if ins.Config == nil || ins.Config.Labels == nil {
						return
					}
					labelVal := strings.TrimSpace(ins.Config.Labels[labelKey])
					if labelVal == "" {
						return
					}
					profile := ensureProfileForLabel(labelVal, profiles)
					if profile == nil {
						return
					}
					if ins.NetworkSettings == nil || len(ins.NetworkSettings.Networks) == 0 {
						return
					}
					ips := extractIPsFromNetworks(ins.NetworkSettings.Networks)
					if len(ips) == 0 {
						return
					}
					name := strings.TrimPrefix(ins.Name, "/")
					shortID := id
					if len(shortID) > 12 {
						shortID = shortID[:12]
					}
					am.UpdateContainer(id, name, profile.Name, ips)
					log.Printf("[events] start: container=%s id=%s profile=%s ips=%v", name, shortID, profile.Name, ips)
				}(containerID)

			case "die", "stop", "destroy":
				am.RemoveContainer(containerID)
				shortID := containerID
				if len(shortID) > 12 {
					shortID = shortID[:12]
				}
				name := evt.Actor.Attributes["name"]
				log.Printf("[events] %s: container=%s id=%s", action, name, shortID)

			default:
				// ignore other actions
			}
		}

		body.Close()
		log.Printf("[events] reconnecting to Docker /events after backoff")
		time.Sleep(backoff)
	}
}

// ProxyServer holds the HTTP handlers state.
type ProxyServer struct {
	docker   *DockerClient
	access   *AccessManager
	profiles map[string]*Profile
	labelKey string
}

func (ps *ProxyServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := ps.docker.Ping(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "docker unreachable: %v\n", err)
		return
	}
	containers, ips := ps.access.Stats()
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "ok containers=%d ips=%d\n", containers, ips)
}

func (ps *ProxyServer) proxyHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	clientIP := normalizeRemoteIP(r.RemoteAddr)
	acc, ok := ps.access.FindByIP(clientIP)
	var profile *Profile
	var profileName, containerName string
	if ok {
		profileName = acc.ProfileName
		containerName = acc.Name
		profile = ps.profiles[profileName]
	} else {
		profileName = "-"
		containerName = "-"
	}

	origPath := r.URL.Path
	endpoint, action, hasVersion, versionIdx, segments := analyzePath(origPath)

	if profile == nil {
		log.Printf("[deny] ip=%s profile=none container=%s method=%s path=%s endpoint=%s action=%s", clientIP, containerName, r.Method, origPath, endpoint, action)
		http.Error(w, "Forbidden: unknown client", http.StatusForbidden)
		return
	}

	if endpoint == "" {
		log.Printf("[deny] ip=%s profile=%s container=%s method=%s path=%s reason=no-endpoint", clientIP, profileName, containerName, r.Method, origPath)
		http.Error(w, "Forbidden: unsupported path", http.StatusForbidden)
		return
	}

	if !isAllowed(profile, r.Method, endpoint, action) {
		log.Printf("[deny] ip=%s profile=%s container=%s method=%s path=%s endpoint=%s action=%s", clientIP, profileName, containerName, r.Method, origPath, endpoint, action)
		http.Error(w, "Forbidden by socket-proxy ACL", http.StatusForbidden)
		return
	}

	// Optional API version rewrite (e.g., v1.44 -> v1.51)
	finalPath := origPath
	if profile.APIRewrite != "" && hasVersion && versionIdx >= 0 && len(segments) > versionIdx {
		segments[versionIdx] = "v" + profile.APIRewrite
		finalPath = "/" + strings.Join(segments, "/")
	}

	// Build upstream request to Docker
	upstreamURL := &url.URL{
		Scheme:   "http",
		Host:     "docker",
		Path:     finalPath,
		RawQuery: r.URL.RawQuery,
	}
	reqUp, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), r.Body)
	if err != nil {
		log.Printf("[error] building upstream request: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	// Copy headers (except hop-by-hop)
	for k, vals := range r.Header {
		if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Keep-Alive") ||
			strings.EqualFold(k, "Proxy-Authenticate") || strings.EqualFold(k, "Proxy-Authorization") ||
			strings.EqualFold(k, "Te") || strings.EqualFold(k, "Trailers") ||
			strings.EqualFold(k, "Transfer-Encoding") || strings.EqualFold(k, "Upgrade") {
			continue
		}
		for _, v := range vals {
			reqUp.Header.Add(k, v)
		}
	}

	respUp, err := ps.docker.httpClient.Do(reqUp)
	if err != nil {
		log.Printf("[error] upstream docker call failed: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer respUp.Body.Close()

	// Copy response headers/status/body
	for k, vals := range respUp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(respUp.StatusCode)
	if _, err := io.Copy(w, respUp.Body); err != nil {
		log.Printf("[warn] error copying upstream response body: %v", err)
	}

	elapsed := time.Since(start)
	log.Printf("[allow] ip=%s profile=%s container=%s method=%s path=%s -> %s endpoint=%s action=%s status=%d duration=%s",
		clientIP, profileName, containerName, r.Method, origPath, finalPath, endpoint, action, respUp.StatusCode, elapsed)
}

func main() {
	log.Printf("=== docker-socket-proxy (Go) starting ===")

	socketPath := os.Getenv("DOCKER_SOCKET_PATH")
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}
	proxyPort := os.Getenv("PROXY_PORT")
	if proxyPort == "" {
		proxyPort = "2375"
	}

	profiles := parseProfilesFromArgs(os.Args[1:])
	if len(profiles) == 0 {
		log.Printf("[warn] no --proxy-*.flags provided: all clients will be denied unless profiles are discovered dynamically")
	}

	labelKey := "socketproxy.service"

	dc := NewDockerClient(socketPath)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := dc.Ping(ctx); err != nil {
		cancel()
		log.Fatalf("docker ping failed on socket %s: %v", socketPath, err)
	}
	cancel()
	log.Printf("[docker] ping OK on %s", socketPath)

	am := NewAccessManager()

	ctxInit, cancelInit := context.WithTimeout(context.Background(), 10*time.Second)
	if err := initialDiscovery(ctxInit, dc, am, profiles, labelKey); err != nil {
		cancelInit()
		log.Printf("[discover] error during initial discovery: %v", err)
	} else {
		cancelInit()
	}

	// Start events watcher
	ctxEvents, cancelEvents := context.WithCancel(context.Background())
	go watchEvents(ctxEvents, dc, am, profiles, labelKey)
	defer cancelEvents()

	ps := &ProxyServer{
		docker:   dc,
		access:   am,
		profiles: profiles,
		labelKey: labelKey,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", ps.healthHandler)
	mux.HandleFunc("/", ps.proxyHandler)

	addr := ":" + proxyPort
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  0,
		WriteTimeout: 0,
	}

	log.Printf("[http] listening on %s (Docker socket: %s)", addr, socketPath)

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("[http] server error: %v", err)
	}
}
