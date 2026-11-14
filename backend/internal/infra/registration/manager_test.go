package registration

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testManager() *Manager {
	return New(Config{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func TestProxyPreservesRequestBodyAndAddsInternalAuth(t *testing.T) {
	var receivedPath string
	var receivedQuery string
	var receivedAuth string
	var receivedBody string
	worker := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		receivedPath = request.URL.Path
		receivedQuery = request.URL.RawQuery
		receivedAuth = request.Header.Get("Authorization")
		body, _ := io.ReadAll(request.Body)
		receivedBody = string(body)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"data":{"ok":true}}`))
	}))
	defer worker.Close()

	manager := testManager()
	manager.baseURL = worker.URL
	manager.token = "worker-token"
	request := httptest.NewRequest(http.MethodPost, "/api/admin/v1/registration/tasks?format=json", strings.NewReader(`{"count":3}`))
	recorder := httptest.NewRecorder()

	manager.Proxy(recorder, request, "/tasks")

	if receivedPath != "/tasks" || receivedQuery != "format=json" {
		t.Fatalf("target = %s?%s", receivedPath, receivedQuery)
	}
	if receivedAuth != "Bearer worker-token" {
		t.Fatalf("authorization = %q", receivedAuth)
	}
	if receivedBody != `{"count":3}` {
		t.Fatalf("body = %q", receivedBody)
	}
	if recorder.Code != http.StatusCreated || !strings.Contains(recorder.Body.String(), `"ok":true`) {
		t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content type = %q", recorder.Header().Get("Content-Type"))
	}
}

func TestResolveRootAndPythonUsesConfiguredPaths(t *testing.T) {
	root := t.TempDir()
	workerPath := filepath.Join(root, "worker.py")
	if err := os.WriteFile(workerPath, []byte("#!/usr/bin/env python3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pythonPath := filepath.Join(root, ".venv", "bin", "python")
	if err := os.MkdirAll(filepath.Dir(pythonPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pythonPath, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	manager := New(Config{RootDir: root, PythonPath: pythonPath})

	resolvedRoot, err := manager.resolveRoot()
	if err != nil {
		t.Fatal(err)
	}
	resolvedPython, err := manager.resolvePython(resolvedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if resolvedRoot != root {
		t.Fatalf("root = %q, want %q", resolvedRoot, root)
	}
	if resolvedPython != pythonPath {
		t.Fatalf("python = %q, want %q", resolvedPython, pythonPath)
	}
}

func TestCloseWithoutStartedWorkerIsNoop(t *testing.T) {
	if err := testManager().Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAvailableLoopbackPortReturnsUsablePort(t *testing.T) {
	port, err := availableLoopbackPort()
	if err != nil {
		t.Fatal(err)
	}
	if port <= 0 || port > 65535 {
		t.Fatalf("port = %d", port)
	}
}

func TestRandomTokenProducesUniqueHexValues(t *testing.T) {
	first, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 64 || len(second) != 64 || first == second {
		t.Fatalf("tokens = %q %q", first, second)
	}
}

func TestStartWithMissingWorkerRootReportsUnavailable(t *testing.T) {
	empty := t.TempDir()
	manager := New(Config{RootDir: empty})
	manager.Start(context.Background())
	status := manager.Status()
	if available, _ := status["available"].(bool); available {
		t.Fatalf("status = %#v", status)
	}
	if _, ok := status["error"].(string); !ok {
		t.Fatalf("status = %#v", status)
	}
}
