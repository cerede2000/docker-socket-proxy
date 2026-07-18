package main

import (
	"context"
	"encoding/json"
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

// eventLoop écoute un flux Docker long-vivant. eventsClient ne doit donc pas
// avoir de timeout global ; discoveryClient reste borné pour les rafraîchissements
// ponctuels déclenchés par les événements.
func eventLoop(ctx context.Context, cfg *ProxyConfig, eventsClient, discoveryClient *http.Client, logger *log.Logger) {
	backoff := 2 * time.Second
	maxBackoff := 30 * time.Second

	// Créer le debouncer avec callback de découverte
	debouncer := newEventDebouncer(cfg.DebounceDelay, func() {
		if err := discoverOnce(ctx, cfg, discoveryClient, logger); err != nil {
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

		resp, err := eventsClient.Do(req)
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
