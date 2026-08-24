package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"
)

func hasDotDotSegment(p string) bool {
	for _, segment := range strings.Split(p, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}

func normalizedDockerPath(rawPath string) (string, bool) {
	if i := strings.Index(rawPath, "?"); i >= 0 {
		rawPath = rawPath[:i]
	}
	if hasDotDotSegment(rawPath) {
		return "", false
	}
	p := pathpkg.Clean("/" + strings.TrimPrefix(rawPath, "/"))
	if p == "/engine/api" {
		p = "/"
	} else if strings.HasPrefix(p, "/engine/api/") {
		p = strings.TrimPrefix(p, "/engine/api")
	}
	return trimAPIVersion(p), true
}

func routeFamily(p, family string) bool {
	return p == family || strings.HasPrefix(p, family+"/")
}

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
	p, ok := normalizedDockerPath(path)
	if !ok {
		return "unknown", ""
	}

	switch {
	case p == "/_ping" || strings.HasPrefix(p, "/_ping/"):
		return "ping", ""
	case p == "/version" || strings.HasPrefix(p, "/version/"):
		return "version", ""
	case p == "/info" || strings.HasPrefix(p, "/info/"):
		return "info", ""
	case routeFamily(p, "/events"):
		return "events", ""
	case routeFamily(p, "/auth"):
		return "auth", ""
	case routeFamily(p, "/build"):
		return "build", ""
	case routeFamily(p, "/commit"):
		return "commit", ""
	case routeFamily(p, "/configs"):
		return "configs", ""
	case routeFamily(p, "/containers"):
		segs := strings.Split(strings.Trim(p, "/"), "/")
		if len(segs) >= 3 {
			switch segs[2] {
			case "archive":
				return "containers", "archive"
			case "changes":
				return "containers", "changes"
			case "export":
				return "containers", "export"
			case "logs":
				return "containers", "logs"
			case "pause":
				return "containers", "pause"
			case "start":
				return "containers", "start"
			case "stop":
				return "containers", "stop"
			case "restart":
				return "containers", "restart"
			case "top":
				return "containers", "top"
			case "unpause":
				return "containers", "unpause"
			case "kill":
				return "containers", "kill"
			case "exec":
				return "containers", "exec"
			case "json":
				return "containers", "inspect"
			}
		}
		return "containers", ""
	case routeFamily(p, "/distribution"):
		return "distribution", ""
	case routeFamily(p, "/exec"):
		return "exec", ""
	case routeFamily(p, "/images"):
		return "images", ""
	case routeFamily(p, "/networks"):
		return "networks", ""
	case routeFamily(p, "/nodes"):
		return "nodes", ""
	case routeFamily(p, "/plugins"):
		return "plugins", ""
	case routeFamily(p, "/secrets"):
		return "secrets", ""
	case routeFamily(p, "/services"):
		return "services", ""
	case routeFamily(p, "/session"):
		return "session", ""
	case routeFamily(p, "/swarm"):
		return "swarm", ""
	case routeFamily(p, "/system"):
		return "system", ""
	case routeFamily(p, "/tasks"):
		return "tasks", ""
	case routeFamily(p, "/volumes"):
		return "volumes", ""
	}
	return "unknown", ""
}

var featurePermissions = map[string]func(*ServiceConfig) bool{
	"ping":         func(s *ServiceConfig) bool { return s.Ping },
	"version":      func(s *ServiceConfig) bool { return s.Version },
	"info":         func(s *ServiceConfig) bool { return s.Info },
	"events":       func(s *ServiceConfig) bool { return s.Events },
	"auth":         func(s *ServiceConfig) bool { return s.Auth },
	"build":        func(s *ServiceConfig) bool { return s.Build },
	"commit":       func(s *ServiceConfig) bool { return s.Commit },
	"configs":      func(s *ServiceConfig) bool { return s.Configs },
	"containers":   func(s *ServiceConfig) bool { return s.Containers },
	"distribution": func(s *ServiceConfig) bool { return s.Distribution },
	"exec":         func(s *ServiceConfig) bool { return s.Exec },
	"images":       func(s *ServiceConfig) bool { return s.Images },
	"networks":     func(s *ServiceConfig) bool { return s.Networks },
	"nodes":        func(s *ServiceConfig) bool { return s.Nodes },
	"plugins":      func(s *ServiceConfig) bool { return s.Plugins },
	"secrets":      func(s *ServiceConfig) bool { return s.Secrets },
	"services":     func(s *ServiceConfig) bool { return s.Services },
	"session":      func(s *ServiceConfig) bool { return s.Session },
	"swarm":        func(s *ServiceConfig) bool { return s.Swarm },
	"system":       func(s *ServiceConfig) bool { return s.System },
	"tasks":        func(s *ServiceConfig) bool { return s.Tasks },
	"volumes":      func(s *ServiceConfig) bool { return s.Volumes },
}

var containerReadPermissions = map[string]func(*ServiceConfig) bool{
	"archive": func(s *ServiceConfig) bool { return s.AllowAll || s.AllowArchive },
	"changes": func(s *ServiceConfig) bool { return s.AllowAll || s.AllowChanges },
	"export":  func(s *ServiceConfig) bool { return s.AllowAll || s.AllowExport },
	"inspect": func(s *ServiceConfig) bool { return s.AllowAll || s.AllowInspect },
	"logs":    func(s *ServiceConfig) bool { return s.AllowAll || s.AllowLogs },
	"top":     func(s *ServiceConfig) bool { return s.AllowAll || s.AllowTop },
}

var containerWritePermissions = map[string]func(*ServiceConfig) bool{
	"pause":   func(s *ServiceConfig) bool { return s.AllowAll || s.AllowPause },
	"start":   func(s *ServiceConfig) bool { return s.AllowAll || s.AllowStart },
	"stop":    func(s *ServiceConfig) bool { return s.AllowAll || s.AllowStop },
	"restart": func(s *ServiceConfig) bool { return s.AllowAll || s.AllowRestart },
	"unpause": func(s *ServiceConfig) bool { return s.AllowAll || s.AllowUnpause },
	"kill":    func(s *ServiceConfig) bool { return s.AllowAll || s.AllowKill },
}

func (s *ServiceConfig) Allow(feature, method, action string) bool {
	isRead := method == http.MethodGet || method == http.MethodHead
	isWrite := method == http.MethodPost || method == http.MethodPut ||
		method == http.MethodPatch || method == http.MethodDelete
	if !isRead && !isWrite {
		return false
	}

	featureAllowed, known := featurePermissions[feature]
	if !known || !featureAllowed(s) {
		return false
	}

	if feature == "containers" && isRead {
		if permission, protected := containerReadPermissions[action]; protected {
			return permission(s)
		}
	}

	if !isWrite {
		return true
	}

	if feature == "containers" {
		if permission, targeted := containerWritePermissions[action]; targeted {
			return permission(s)
		}
		// Creating an exec session is both a generic Docker write and an exec
		// capability. Requiring both permissions prevents post from silently
		// becoming remote command execution.
		if action == "exec" {
			return s.Post && s.Exec
		}
	}

	return s.Post
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
	meta := dockerContainerMeta{ID: inspect.ID, Name: normalizeContainerRef(inspect.Name)}
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
	p, ok := normalizedDockerPath(path)
	if !ok {
		return ""
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

func filterContainerListResponse(resp *http.Response, service *ServiceConfig) {
	originalBody := resp.Body
	ctx := context.Background()
	if resp.Request != nil {
		ctx = resp.Request.Context()
	}
	stopClose := context.AfterFunc(ctx, func() { _ = originalBody.Close() })
	reader, writer := io.Pipe()
	resp.Body = reader
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")

	go func() {
		defer stopClose()
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
	ctx := context.Background()
	if resp.Request != nil {
		ctx = resp.Request.Context()
	}
	stopClose := context.AfterFunc(ctx, func() { _ = originalBody.Close() })
	reader, writer := io.Pipe()
	resp.Body = reader
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")

	go func() {
		defer stopClose()
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
			meta := dockerContainerMeta{ID: event.Actor.ID, Name: normalizeContainerRef(event.Actor.Attributes["name"])}
			if meta.Name == "" {
				var ok bool
				meta, ok = cfg.GetContainer(event.Actor.ID)
				if !ok {
					continue
				}
			}
			if !service.AllowsContainer(meta) {
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
		if encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
			return fmt.Errorf("cannot safely scope Docker response with content encoding %q", encoding)
		}
		switch filter.kind {
		case filterContainerList:
			filterContainerListResponse(resp, filter.service)
		case filterEvents:
			filterEventsResponse(resp, cfg, filter.service)
		}
		return nil
	}
}

// -----------------------------
// Handler HTTP / proxy
// -----------------------------
