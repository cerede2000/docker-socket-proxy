package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// defaultUnixSocketMode restreint la socket au propriétaire et à son groupe.
// Le consommateur doit partager l'UID ou le GID du proxy pour s'y connecter.
const defaultUnixSocketMode os.FileMode = 0o660

// listenDisabled désactive explicitement l'écoute TCP. Le proxy ne sert alors
// que des sockets unix, ce qui supprime toute exposition réseau.
const listenDisabled = "off"

// UnixListenerConfig associe une socket unix à un profil unique. Le chemin de
// la socket porte l'identité du client : les permissions du système de fichiers
// remplacent l'association IP → rôle utilisée sur le frontend TCP.
type UnixListenerConfig struct {
	Path string
	Role string
}

func isListenDisabled(addr string) bool {
	switch strings.ToLower(strings.TrimSpace(addr)) {
	case listenDisabled, "none", "disabled":
		return true
	default:
		return false
	}
}

// parseUnixListener lit une entrée "<chemin>:<rôle>". Le rôle ne pouvant pas
// contenir de deux-points, la césure se fait sur le dernier séparateur, ce qui
// laisse passer les chemins exotiques.
func parseUnixListener(value string) (UnixListenerConfig, error) {
	raw := strings.TrimSpace(value)
	idx := strings.LastIndex(raw, ":")
	if idx <= 0 || idx == len(raw)-1 {
		return UnixListenerConfig{}, fmt.Errorf("listen-unix entry %q must use <path>:<role>", value)
	}
	path := strings.TrimSpace(raw[:idx])
	role := normalizeRoleName(raw[idx+1:])
	if path == "" || role == "" {
		return UnixListenerConfig{}, fmt.Errorf("listen-unix entry %q must use <path>:<role>", value)
	}
	if !filepath.IsAbs(path) {
		return UnixListenerConfig{}, fmt.Errorf("listen-unix path %q must be absolute", path)
	}
	return UnixListenerConfig{Path: path, Role: role}, nil
}

// parseUnixListeners accepte plusieurs entrées séparées par des virgules ou des
// sauts de ligne, et refuse les doublons de chemin.
func parseUnixListeners(value string) ([]UnixListenerConfig, error) {
	var out []UnixListenerConfig
	seen := make(map[string]struct{})
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' }) {
		if strings.TrimSpace(field) == "" {
			continue
		}
		entry, err := parseUnixListener(field)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[entry.Path]; dup {
			return nil, fmt.Errorf("listen-unix path %q is declared twice", entry.Path)
		}
		seen[entry.Path] = struct{}{}
		out = append(out, entry)
	}
	return out, nil
}

// validateUnixListeners contrôle la cohérence globale, que les entrées viennent
// de l'environnement ou de plusieurs --listen-unix accumulés.
func validateUnixListeners(cfg *ProxyConfig) error {
	seen := make(map[string]struct{}, len(cfg.UnixListeners))
	for _, entry := range cfg.UnixListeners {
		if _, dup := seen[entry.Path]; dup {
			return fmt.Errorf("listen-unix path %q is declared twice", entry.Path)
		}
		seen[entry.Path] = struct{}{}
	}
	if isListenDisabled(cfg.Listen) && len(cfg.UnixListeners) == 0 {
		return fmt.Errorf("listen is disabled but no --listen-unix is declared: the proxy would accept nothing")
	}
	return nil
}

func parseSocketMode(value string) (os.FileMode, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return defaultUnixSocketMode, nil
	}
	parsed, err := strconv.ParseUint(raw, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid socket mode %q (expected octal such as 0660)", value)
	}
	if parsed > 0o777 {
		return 0, fmt.Errorf("invalid socket mode %q (expected octal such as 0660)", value)
	}
	return os.FileMode(parsed), nil
}

// removeStaleSocket efface une socket laissée par un arrêt brutal. Tout autre
// type de fichier est laissé en place : le proxy ne doit jamais supprimer un
// fichier qu'il n'a pas créé lui-même.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to remove %q: not a socket", path)
	}
	return os.Remove(path)
}

// listenUnix crée la socket sans aucune permission, puis applique le mode
// demandé.
//
// Le chmod suffirait à obtenir le mode final ; le umask sert à la fenêtre qui
// le précède. Sans lui, la socket existerait un instant avec les permissions
// par défaut du processus — 0755 pour un umask courant de 0022 — et serait
// joignable par n'importe qui pendant ce laps de temps.
//
// Le masque étant global au processus, cette fonction doit être appelée avant
// le démarrage des boucles de fond ; main s'en charge.
func listenUnix(path string, mode os.FileMode) (net.Listener, error) {
	if err := removeStaleSocket(path); err != nil {
		return nil, err
	}

	previousMask := syscall.Umask(0o777)
	listener, err := net.Listen("unix", path)
	syscall.Umask(previousMask)
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(path, mode); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("chmod %q: %w", path, err)
	}
	return listener, nil
}

// boundListener retient le rôle imposé par une socket unix. Une valeur vide
// signifie que le rôle doit être déduit de l'adresse IP du client.
type boundListener struct {
	listener net.Listener
	role     string
}

type boundRoleContextKey struct{}

// withBoundRole marque chaque requête arrivée sur une socket unix dédiée. Le
// rôle est imposé par le listener, jamais déduit de la requête elle-même : un
// client ne peut donc pas influencer le profil qui lui est appliqué.
func withBoundRole(next http.Handler, role string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), boundRoleContextKey{}, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func boundRoleFromContext(ctx context.Context) (string, bool) {
	role, ok := ctx.Value(boundRoleContextKey{}).(string)
	return role, ok
}

// buildListeners ouvre le frontend TCP puis chaque socket unix. En cas d'échec
// partiel, les listeners déjà ouverts sont refermés pour ne pas laisser de
// socket orpheline derrière soi.
func buildListeners(cfg *ProxyConfig, logger *log.Logger) ([]boundListener, error) {
	var listeners []boundListener

	closeAll := func() {
		for _, bound := range listeners {
			_ = bound.listener.Close()
		}
	}

	if !isListenDisabled(cfg.Listen) {
		listener, err := net.Listen("tcp", cfg.Listen)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, boundListener{listener: listener})
		logger.Printf("[main] listening on tcp %s (role resolved from client IP)", cfg.Listen)
	}

	for _, entry := range cfg.UnixListeners {
		listener, err := listenUnix(entry.Path, cfg.UnixSocketMode)
		if err != nil {
			closeAll()
			return nil, err
		}
		listeners = append(listeners, boundListener{listener: listener, role: entry.Role})
		logger.Printf("[main] listening on unix %s mode=%#o role=%q",
			entry.Path, cfg.UnixSocketMode, entry.Role)
	}

	if len(listeners) == 0 {
		return nil, fmt.Errorf("no listener configured: enable the TCP frontend or declare at least one --listen-unix")
	}
	return listeners, nil
}
