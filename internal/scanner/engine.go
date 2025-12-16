package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/dtang19/mcptrust/internal/models"
)

const (
	// DefaultTimeout is the default timeout for MCP operations
	DefaultTimeout = 10 * time.Second

	// MCPProtocolVersion supported
	MCPProtocolVersion = "2024-11-05"
)

// dangerousKeywords flag risky tools
var dangerousKeywords = []string{
	"exec", "shell", "write", "delete", "fs", "run", "execute",
	"bash", "command", "sudo", "rm", "remove", "kill", "spawn",
	"eval", "system", "popen", "subprocess", "terminal",
}

// Engine interacts with MCP servers
type Engine struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    *bufio.Reader
	stderr    io.ReadCloser
	requestID int
	mu        sync.Mutex
	timeout   time.Duration
}

func NewEngine(timeout time.Duration) *Engine {
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	return &Engine{
		timeout:   timeout,
		requestID: 0,
	}
}

// Connect starts process
func (e *Engine) Connect(ctx context.Context, command string) error {
	// parse cmd
	parts := parseCommand(command)
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	e.cmd = exec.CommandContext(ctx, parts[0], parts[1:]...)

	// pipes
	var err error
	e.stdin, err = e.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := e.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	e.stdout = bufio.NewReader(stdout)

	e.stderr, err = e.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// start
	if err := e.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start MCP server: %w", err)
	}

	return nil
}

// Initialize handshake
func (e *Engine) Initialize(ctx context.Context) (*models.ServerInfo, error) {
	req := models.MCPInitializeRequest{
		JSONRPC: "2.0",
		ID:      e.nextID(),
		Method:  "initialize",
		Params: models.MCPInitializeParams{
			ProtocolVersion: MCPProtocolVersion,
			Capabilities:    models.MCPCapabilities{},
			ClientInfo: models.MCPClientInfo{
				Name:    "mcptrust",
				Version: "1.0.0",
			},
		},
	}

	var resp models.MCPInitializeResponse
	if err := e.sendRequest(ctx, req, &resp); err != nil {
		return nil, fmt.Errorf("initialize request failed: %w", err)
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("MCP error: %s (code: %d)", resp.Error.Message, resp.Error.Code)
	}

	if resp.Result == nil {
		return nil, fmt.Errorf("empty initialize response")
	}

	// Send initialized notification
	notification := models.MCPNotification{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}
	if err := e.sendNotification(notification); err != nil {
		return nil, fmt.Errorf("failed to send initialized notification: %w", err)
	}

	return &models.ServerInfo{
		Name:            resp.Result.ServerInfo.Name,
		Version:         resp.Result.ServerInfo.Version,
		ProtocolVersion: resp.Result.ProtocolVersion,
	}, nil
}

// ListTools retrieves all available tools from the MCP server
func (e *Engine) ListTools(ctx context.Context) ([]models.MCPTool, error) {
	req := models.MCPListRequest{
		JSONRPC: "2.0",
		ID:      e.nextID(),
		Method:  "tools/list",
	}

	var resp models.MCPToolsListResponse
	if err := e.sendRequest(ctx, req, &resp); err != nil {
		return nil, fmt.Errorf("tools/list request failed: %w", err)
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("MCP error: %s (code: %d)", resp.Error.Message, resp.Error.Code)
	}

	if resp.Result == nil {
		return []models.MCPTool{}, nil
	}

	return resp.Result.Tools, nil
}

// ListResources retrieves all available resources from the MCP server
func (e *Engine) ListResources(ctx context.Context) ([]models.MCPResource, error) {
	req := models.MCPListRequest{
		JSONRPC: "2.0",
		ID:      e.nextID(),
		Method:  "resources/list",
	}

	var resp models.MCPResourcesListResponse
	if err := e.sendRequest(ctx, req, &resp); err != nil {
		return nil, fmt.Errorf("resources/list request failed: %w", err)
	}

	if resp.Error != nil {
		// Some servers don't support resources - treat as empty list
		return []models.MCPResource{}, nil
	}

	if resp.Result == nil {
		return []models.MCPResource{}, nil
	}

	return resp.Result.Resources, nil
}

// Close terminates the MCP server process
func (e *Engine) Close() error {
	if e.stdin != nil {
		e.stdin.Close()
	}
	if e.stderr != nil {
		e.stderr.Close()
	}
	if e.cmd != nil && e.cmd.Process != nil {
		// Give the process a chance to exit gracefully
		done := make(chan error, 1)
		go func() {
			done <- e.cmd.Wait()
		}()

		select {
		case <-done:
			// Process exited
		case <-time.After(2 * time.Second):
			// Force kill
			if err := e.cmd.Process.Kill(); err != nil {
				return fmt.Errorf("failed to kill process: %w", err)
			}
		}
	}
	return nil
}

// sendRequest sends a JSON-RPC request and reads the response
func (e *Engine) sendRequest(ctx context.Context, req interface{}, resp interface{}) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Marshal request
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send request with newline
	if _, err := e.stdin.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write request: %w", err)
	}

	// Read response with timeout
	responseChan := make(chan []byte, 1)
	errorChan := make(chan error, 1)

	go func() {
		line, err := e.stdout.ReadBytes('\n')
		if err != nil {
			errorChan <- err
			return
		}
		responseChan <- line
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errorChan:
		return fmt.Errorf("failed to read response: %w", err)
	case line := <-responseChan:
		if err := json.Unmarshal(line, resp); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
		return nil
	}
}

// sendNotification sends a JSON-RPC notification (no response expected)
func (e *Engine) sendNotification(notification interface{}) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	data, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to marshal notification: %w", err)
	}

	if _, err := e.stdin.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write notification: %w", err)
	}

	return nil
}

// nextID returns the next request ID
func (e *Engine) nextID() int {
	e.requestID++
	return e.requestID
}

// parseCommand splits a command string into parts, respecting quotes
func parseCommand(command string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	quoteChar := rune(0)

	for _, r := range command {
		switch {
		case (r == '"' || r == '\'') && !inQuotes:
			inQuotes = true
			quoteChar = r
		case r == quoteChar && inQuotes:
			inQuotes = false
			quoteChar = 0
		case r == ' ' && !inQuotes:
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}

// RiskAnalyzer analyzes tools for security risks
type RiskAnalyzer struct{}

// NewRiskAnalyzer creates a new risk analyzer
func NewRiskAnalyzer() *RiskAnalyzer {
	return &RiskAnalyzer{}
}

// AnalyzeTools assesses the risk level of each tool
func (ra *RiskAnalyzer) AnalyzeTools(mcpTools []models.MCPTool) []models.Tool {
	tools := make([]models.Tool, 0, len(mcpTools))

	for _, t := range mcpTools {
		tool := models.Tool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		}

		// Analyze risk
		tool.RiskLevel, tool.RiskReasons = ra.assessRisk(t)
		tools = append(tools, tool)
	}

	return tools
}

// assessRisk determines the risk level based on tool name and description
func (ra *RiskAnalyzer) assessRisk(tool models.MCPTool) (models.RiskLevel, []string) {
	var reasons []string
	searchText := strings.ToLower(tool.Name + " " + tool.Description)

	for _, keyword := range dangerousKeywords {
		if strings.Contains(searchText, keyword) {
			reasons = append(reasons, fmt.Sprintf("contains dangerous keyword: %q", keyword))
		}
	}

	// Determine risk level based on number of matches
	switch {
	case len(reasons) >= 2:
		return models.RiskLevelHigh, reasons
	case len(reasons) == 1:
		return models.RiskLevelMedium, reasons
	default:
		return models.RiskLevelLow, nil
	}
}

// Scan runs valid security check
func Scan(ctx context.Context, command string, timeout time.Duration) (*models.ScanReport, error) {
	report := &models.ScanReport{
		Timestamp: time.Now().UTC(),
		Command:   command,
		Tools:     []models.Tool{},
		Resources: []models.Resource{},
	}

	// timeout ctx
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// connect
	engine := NewEngine(timeout)
	if err := engine.Connect(ctx, command); err != nil {
		report.Error = err.Error()
		return report, nil
	}
	defer engine.Close()

	// handshake
	serverInfo, err := engine.Initialize(ctx)
	if err != nil {
		report.Error = fmt.Sprintf("initialization failed: %v", err)
		return report, nil
	}
	report.ServerInfo = serverInfo

	// list tools
	mcpTools, err := engine.ListTools(ctx)
	if err != nil {
		report.Error = fmt.Sprintf("failed to list tools: %v", err)
		return report, nil
	}

	// risk
	analyzer := NewRiskAnalyzer()
	report.Tools = analyzer.AnalyzeTools(mcpTools)

	// resources
	mcpResources, err := engine.ListResources(ctx)
	if err != nil {
		// Non-fatal, some servers don't support resources
		report.Resources = []models.Resource{}
	} else {
		for _, r := range mcpResources {
			report.Resources = append(report.Resources, models.Resource(r))
		}
	}

	return report, nil
}
