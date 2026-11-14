package registration

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	startupTimeout = 35 * time.Second
	requestTimeout = 3 * time.Minute
)

// Config controls the local Python registration worker managed by the Go app.
// The worker is deliberately loopback-only and never exposed as a public port.
type Config struct {
	RootDir    string
	DataDir    string
	PythonPath string
	Callback   string
	// CallbackToken authenticates the Python worker to the Go internal ingest
	// endpoints. It is generated once by the application and never exposed.
	CallbackToken string
	Logger        *slog.Logger
}

// Manager owns the worker process lifecycle and proxies administrator requests
// to its random loopback port with a process-scoped bearer token.
type Manager struct {
	config Config
	client *http.Client

	mu        sync.RWMutex
	command   *exec.Cmd
	cancel    context.CancelFunc
	baseURL   string
	token     string
	startErr  error
	startedAt time.Time
}

func New(config Config) *Manager {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Manager{
		config: config,
		client: &http.Client{
			Timeout: requestTimeout,
			Transport: &http.Transport{
				Proxy:                 nil,
				MaxIdleConns:          8,
				MaxIdleConnsPerHost:   4,
				IdleConnTimeout:       30 * time.Second,
				ResponseHeaderTimeout: requestTimeout,
			},
		},
	}
}

// Start launches the worker without making the main service dependent on
// browser automation packages at boot. Startup errors are surfaced in status
// and on registration routes while the rest of the API remains available.
func (m *Manager) Start(parent context.Context) {
	m.mu.Lock()
	if m.command != nil {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel
	m.mu.Unlock()

	err := m.start(ctx)
	m.mu.Lock()
	m.startErr = err
	if err == nil {
		m.startedAt = time.Now().UTC()
	}
	m.mu.Unlock()
	if err != nil {
		m.config.Logger.Warn("registration_worker_unavailable", "error", err)
	}
}

func (m *Manager) start(ctx context.Context) error {
	root, err := m.resolveRoot()
	if err != nil {
		return err
	}
	python, err := m.resolvePython(root)
	if err != nil {
		return err
	}
	dataDir := strings.TrimSpace(m.config.DataDir)
	if dataDir == "" {
		dataDir = filepath.Join(root, ".data")
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return fmt.Errorf("解析注册数据目录: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("创建注册数据目录: %w", err)
	}
	_ = os.Chmod(dataDir, 0o700)

	port, err := availableLoopbackPort()
	if err != nil {
		return fmt.Errorf("分配注册 Worker 端口: %w", err)
	}
	token, err := randomToken()
	if err != nil {
		return err
	}
	callback := strings.TrimSpace(m.config.Callback)
	if callback == "" {
		return errors.New("缺少 Go 注册回调地址")
	}
	callbackToken := strings.TrimSpace(m.config.CallbackToken)
	if len(callbackToken) < 24 {
		return errors.New("Go 注册回调令牌缺失或过短")
	}
	parsed, err := url.Parse(callback)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("Go 注册回调地址无效")
	}

	command := exec.CommandContext(
		ctx,
		python,
		filepath.Join(root, "worker.py"),
		"--host", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--data-dir", dataDir,
		"--callback-url", callback,
	)
	command.Dir = root
	command.Env = append(os.Environ(),
		"GROK2API_REGISTRATION_WORKER_TOKEN="+token,
		"GROK2API_REGISTRATION_CALLBACK_TOKEN="+callbackToken,
		"PYTHONUNBUFFERED=1",
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("连接注册 Worker 标准输出: %w", err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return fmt.Errorf("连接注册 Worker 标准错误: %w", err)
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("启动注册 Worker: %w", err)
	}

	m.mu.Lock()
	m.command = command
	m.baseURL = "http://127.0.0.1:" + strconv.Itoa(port)
	m.token = token
	m.mu.Unlock()
	go m.relayOutput("stdout", stdout)
	go m.relayOutput("stderr", stderr)

	if err := m.waitForHealth(ctx, port, token); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		m.mu.Lock()
		m.command = nil
		m.baseURL = ""
		m.token = ""
		m.mu.Unlock()
		return err
	}
	m.config.Logger.Info("registration_worker_started", "root", root, "data_dir", dataDir, "port", port)
	return nil
}

func (m *Manager) resolveRoot() (string, error) {
	candidates := make([]string, 0, 8)
	appendCandidate := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			candidates = append(candidates, value)
		}
	}
	appendCandidate(os.Getenv("GROK2API_REGISTRATION_ROOT"))
	appendCandidate(m.config.RootDir)
	if cwd, err := os.Getwd(); err == nil {
		appendCandidate(filepath.Join(cwd, "registration"))
		appendCandidate(filepath.Join(cwd, "..", "registration"))
	}
	if executable, err := os.Executable(); err == nil {
		dir := filepath.Dir(executable)
		appendCandidate(filepath.Join(dir, "registration"))
		appendCandidate(filepath.Join(dir, "..", "registration"))
	}
	for _, candidate := range candidates {
		worker := filepath.Join(candidate, "worker.py")
		if info, err := os.Stat(worker); err == nil && !info.IsDir() {
			return filepath.Abs(candidate)
		}
	}
	return "", errors.New("找不到 registration/worker.py，请设置 GROK2API_REGISTRATION_ROOT")
}

func (m *Manager) resolvePython(root string) (string, error) {
	candidates := make([]string, 0, 5)
	if configured := strings.TrimSpace(m.config.PythonPath); configured != "" {
		candidates = append(candidates, configured)
	}
	if configured := strings.TrimSpace(os.Getenv("GROK2API_REGISTRATION_PYTHON")); configured != "" {
		candidates = append(candidates, configured)
	}
	candidates = append(candidates,
		filepath.Join(root, ".venv", "bin", "python"),
		filepath.Join(root, "..", ".venv", "bin", "python"),
	)
	for _, candidate := range candidates {
		if strings.ContainsRune(candidate, filepath.Separator) {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
			continue
		}
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved, nil
		}
	}
	for _, candidate := range []string{"python3", "python"} {
		if resolved, err := exec.LookPath(candidate); err == nil {
			return resolved, nil
		}
	}
	return "", errors.New("找不到 Python，请设置 GROK2API_REGISTRATION_PYTHON")
}

func availableLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return 0, errors.New("无法读取临时端口")
	}
	return address.Port, nil
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("生成内部认证令牌: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func (m *Manager) waitForHealth(ctx context.Context, port int, token string) error {
	deadline := time.Now().Add(startupTimeout)
	healthURL := "http://127.0.0.1:" + strconv.Itoa(port) + "/healthz"
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := (&http.Client{Timeout: 2 * time.Second}).Do(request)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 16<<10))
			response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK {
				var payload struct {
					Data struct {
						OK         bool `json:"ok"`
						Configured bool `json:"configured"`
					} `json:"data"`
				}
				_ = json.Unmarshal(body, &payload)
				if payload.Data.OK {
					if !payload.Data.Configured {
						m.config.Logger.Warn("registration_worker_dependencies_incomplete")
					}
					return nil
				}
			}
			lastErr = fmt.Errorf("健康检查 HTTP %d", response.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("启动超时")
	}
	return fmt.Errorf("等待注册 Worker 就绪: %w", lastErr)
}

func (m *Manager) relayOutput(stream string, reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.Contains(line, "registration_worker_ready") {
			m.config.Logger.Info("registration_worker_ready")
			continue
		}
		m.config.Logger.Info("registration_worker_output", "stream", stream, "message", line)
	}
}

// Close terminates the worker and waits briefly for cooperative shutdown.
func (m *Manager) Close() error {
	m.mu.Lock()
	cancel := m.cancel
	command := m.command
	m.cancel = nil
	m.command = nil
	m.baseURL = ""
	m.token = ""
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if command == nil || command.Process == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		_ = command.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		<-done
		return errors.New("注册 Worker 未在超时内退出，已强制结束")
	}
}

// Status is safe to expose through an authenticated administrator endpoint.
func (m *Manager) Status() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	value := map[string]any{
		"available": m.baseURL != "",
		"startedAt": m.startedAt,
	}
	if m.startErr != nil {
		value["error"] = m.startErr.Error()
	}
	return value
}

// Proxy forwards an authenticated administrator request to the random local
// worker port. The worker response body and content type are preserved.
func (m *Manager) Proxy(writer http.ResponseWriter, request *http.Request, path string) {
	m.mu.RLock()
	baseURL := m.baseURL
	token := m.token
	startErr := m.startErr
	m.mu.RUnlock()
	if baseURL == "" {
		if startErr == nil {
			startErr = errors.New("注册 Worker 尚未就绪")
		}
		http.Error(writer, startErr.Error(), http.StatusServiceUnavailable)
		return
	}
	target := baseURL + path
	if request.URL.RawQuery != "" {
		target += "?" + request.URL.RawQuery
	}
	proxyRequest, err := http.NewRequestWithContext(request.Context(), request.Method, target, request.Body)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	proxyRequest.Header = request.Header.Clone()
	// The Python BaseHTTPRequestHandler reads JSON by Content-Length. Without
	// copying this field, Go can forward an io.ReadCloser as chunked and the
	// worker parses the payload as an empty object.
	proxyRequest.ContentLength = request.ContentLength
	proxyRequest.Header.Set("Authorization", "Bearer "+token)
	response, err := m.client.Do(proxyRequest)
	if err != nil {
		http.Error(writer, "注册 Worker 请求失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	for key, values := range response.Header {
		if strings.EqualFold(key, "Connection") || strings.EqualFold(key, "Transfer-Encoding") {
			continue
		}
		for _, value := range values {
			writer.Header().Add(key, value)
		}
	}
	writer.WriteHeader(response.StatusCode)
	_, _ = io.Copy(writer, response.Body)
}
