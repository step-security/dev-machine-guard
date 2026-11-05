//go:build linux

// Package containerlife owns the Linux container runtime and its local process/state boundary.
package containerlife

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"golang.org/x/sys/unix"
)

type runtimeState struct {
	DeviceID   string `json:"device_id"`
	StartID    string `json:"start_id"`
	Generation int64  `json:"generation"`
	Sequence   int64  `json:"sequence"`
	Stopped    bool   `json:"stopped"`
}

type runtime struct {
	dir, binary string
	state       runtimeState
	cfg         config.ConfigFile
	client      *http.Client
	metadata    *model.ContainerMetadata
}

func Run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: container setup|start|stop|scripts --output DIR")
	}
	fs := flag.NewFlagSet("container", flag.ContinueOnError)
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := fs.String("state-dir", filepath.Join(home, ".stepsecurity", "container"), "private per-container state directory")
	output := fs.String("output", "", "script output directory")
	workspace := fs.String("workspace-name", "", "workspace label (setup only)")
	repository := fs.String("repository-url", "", "HTTPS repository URL (setup only)")
	environment := fs.String("environment", "", "docker, devcontainer or codespaces (setup only)")
	if err = fs.Parse(args[1:]); err != nil {
		return err
	}
	provided := map[string]string{}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "workspace-name":
			provided[f.Name] = *workspace
		case "repository-url":
			provided[f.Name] = *repository
		case "environment":
			provided[f.Name] = *environment
		}
	})
	if len(provided) > 0 && args[0] != "setup" {
		return fmt.Errorf("metadata flags are only supported by container setup")
	}
	if err := validateMetadata(model.ContainerMetadata{WorkspaceName: *workspace, RepositoryURL: *repository, Environment: *environment}); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	if args[0] == "scripts" {
		return WriteScripts(*output)
	}
	if args[0] != "setup" && args[0] != "start" && args[0] != "stop" && args[0] != "run" {
		return fmt.Errorf("unknown container command %q", args[0])
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	r := runtime{dir: abs, binary: binary, client: &http.Client{Timeout: 5 * time.Second}}
	if args[0] == "stop" {
		return r.control("stop", 35*time.Second)
	}
	if args[0] == "run" {
		return r.run()
	}
	if err = r.setup(); err != nil {
		return err
	}
	if args[0] == "setup" {
		return r.configureMetadata(provided)
	}
	if err = r.control("ping", time.Second); err == nil {
		return nil
	}
	if err = executor.NewReal().StartDetached(binary, "container", "run", "--state-dir", abs); err != nil {
		return err
	}
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		if r.control("ping", time.Second) == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("container agent did not become ready; check configuration and API connectivity")
}

func (r *runtime) statePath() string  { return filepath.Join(r.dir, "state.json") }
func (r *runtime) configPath() string { return filepath.Join(r.dir, "config.json") }
func (r *runtime) socketPath() string { return filepath.Join(r.dir, "control.sock") }
func (r *runtime) save() error {
	b, err := json.Marshal(r.state)
	if err != nil {
		return err
	}
	tmp := r.statePath() + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, r.statePath())
}
func (r *runtime) load() error {
	b, err := os.ReadFile(r.statePath())
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, &r.state); err != nil {
		return err
	}
	b, err = os.ReadFile(r.configPath())
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &r.cfg)
}
func (r *runtime) acquire(name string) (*os.File, error) {
	root, err := os.OpenRoot(r.dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	fd := f.Fd()
	if fd > uintptr(1<<(strconv.IntSize-1)-1) {
		_ = f.Close()
		return nil, fmt.Errorf("file descriptor exceeds platform integer range")
	}
	if err = unix.Flock(int(fd), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
func (r *runtime) setup() error {
	if err := os.MkdirAll(r.dir, 0700); err != nil {
		return err
	}
	f, err := r.acquire("setup.lock")
	if err != nil {
		return fmt.Errorf("container setup busy: %w", err)
	}
	defer f.Close()
	if err = r.load(); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	var cfg config.ConfigFile
	b, err := os.ReadFile(config.ConfigFilePath())
	if err == nil {
		if err = json.Unmarshal(b, &cfg); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	for key, dst := range map[string]*string{"DMG_CUSTOMER_ID": &cfg.CustomerID, "DMG_API_ENDPOINT": &cfg.APIEndpoint, "DMG_API_KEY": &cfg.APIKey} {
		if v := os.Getenv(key); v != "" {
			*dst = v
		}
	}
	if cfg.CustomerID == "" || cfg.APIEndpoint == "" || cfg.APIKey == "" {
		return fmt.Errorf("configure DMG or provide DMG_CUSTOMER_ID, DMG_API_ENDPOINT and DMG_API_KEY")
	}
	if r.state.DeviceID == "" {
		r.state.DeviceID = "container-" + uuid.NewString()
	}
	cfg.DeviceID = r.state.DeviceID
	cfg.InstallDir = r.dir
	r.cfg = cfg
	b, err = json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err = os.WriteFile(r.configPath(), b, 0600); err != nil {
		return err
	}
	return r.save()
}
func (r *runtime) control(command string, timeout time.Duration) error {
	c, err := net.DialTimeout("unix", r.socketPath(), time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err = fmt.Fprintln(c, command); err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(c, 4096))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(b)) != "ok" {
		return fmt.Errorf("container agent: %s", strings.TrimSpace(string(b)))
	}
	return nil
}
func (r *runtime) event(kind string) error {
	req := model.ContainerLifecycleEvent{DeviceID: r.state.DeviceID, Event: kind, Generation: r.state.Generation, Sequence: r.state.Sequence}
	if kind == "start" {
		req.StartID = r.state.StartID
		req.Metadata = r.metadata
		req.Hostname, _ = os.Hostname()
	}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	url := strings.TrimRight(r.cfg.APIEndpoint, "/") + "/v1/" + r.cfg.CustomerID + "/developer-mdm-agent/container-lifecycle"
	for attempt := 0; attempt < 3; attempt++ {
		request, e := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
		if e != nil {
			return e
		}
		request.Header.Set("Authorization", "Bearer "+r.cfg.APIKey)
		request.Header.Set("Content-Type", "application/json")
		response, e := r.client.Do(request)
		if e != nil {
			err = e
			continue
		}
		var result model.ContainerLifecycleResponse
		e = json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&result)
		_ = response.Body.Close()
		if response.StatusCode >= 400 {
			err = fmt.Errorf("lifecycle API returned HTTP %d", response.StatusCode)
			if response.StatusCode < 500 {
				return err
			}
			continue
		}
		if e != nil {
			return e
		}
		if kind == "start" {
			if result.Lifecycle.Generation < 1 {
				return fmt.Errorf("invalid lifecycle generation")
			}
			r.state.Generation = result.Lifecycle.Generation
			return r.save()
		}
		if kind == "stop" && result.Lifecycle.Status == "stopped" && result.Lifecycle.Generation == r.state.Generation && result.Lifecycle.Sequence == r.state.Sequence {
			return nil
		}
		if result.Accepted != nil && !*result.Accepted {
			return fmt.Errorf("lifecycle event rejected as stale")
		}
		return nil
	}
	return err
}
func (r *runtime) run() error {
	f, err := r.acquire("runtime.lock")
	if err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil
		}
		return err
	}
	defer f.Close()
	if err = r.load(); err != nil {
		return err
	}
	if r.metadata, err = readMetadata(r.dir); err != nil {
		return err
	}
	if r.state.StartID == "" || r.state.Stopped || r.state.Generation > 0 {
		r.state.StartID = uuid.NewString()
		r.state.Generation = 0
		r.state.Sequence = 0
		r.state.Stopped = false
		if err = r.save(); err != nil {
			return err
		}
	}
	if err = r.event("start"); err != nil {
		return err
	}
	// Only the lock owner may replace a stale socket from a previous process.
	if err = os.Remove(r.socketPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", r.socketPath())
	if err != nil {
		return err
	}
	defer listener.Close()
	stop := make(chan net.Conn)
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(35 * time.Second))
			var cmd string
			_, e = fmt.Fscanln(c, &cmd)
			if e != nil {
				_ = c.Close()
				continue
			}
			if cmd == "stop" {
				select {
				case stop <- c:
				case <-time.After(time.Second):
					_ = c.Close()
				}
			} else {
				_, _ = fmt.Fprintln(c, "ok")
				_ = c.Close()
			}
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		interval := time.Hour
		if h, e := strconv.ParseFloat(r.cfg.ScanFrequencyHours, 64); e == nil && h > 0 {
			interval = time.Duration(h * float64(time.Hour))
		}
		for {
			_, stderr, _, e := executor.NewReal().RunWithTimeout(ctx, 30*time.Minute, r.binary, "send-telemetry", "--config", r.configPath())
			if e != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "container scan failed: %v %s\n", e, stderr)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
			}
		}
	}()
	defer func() { cancel(); <-scanDone }()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case c := <-stop:
			cancel()
			<-scanDone
			r.state.Sequence++
			r.state.Stopped = true
			err = r.save()
			if err == nil {
				err = r.event("stop")
			}
			if err != nil {
				_, _ = fmt.Fprintln(c, err)
			} else {
				_, _ = fmt.Fprintln(c, "ok")
			}
			_ = c.Close()
			return err
		case <-ticker.C:
			r.state.Sequence++
			if err = r.save(); err != nil {
				return err
			}
			if err = r.event("heartbeat"); err != nil {
				fmt.Fprintln(os.Stderr, "container heartbeat:", err)
			}
		}
	}
}
