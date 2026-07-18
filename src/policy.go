package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

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
