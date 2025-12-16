package models

import "time"

// RiskLevel enum
type RiskLevel string

const (
	RiskLevelLow    RiskLevel = "LOW"
	RiskLevelMedium RiskLevel = "MEDIUM"
	RiskLevelHigh   RiskLevel = "HIGH"
)

// Tool definition
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
	RiskLevel   RiskLevel              `json:"riskLevel"`
	RiskReasons []string               `json:"riskReasons,omitempty"`
}

// Resource definition
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type ServerInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	ProtocolVersion string `json:"protocolVersion"`
}

// ScanReport result
type ScanReport struct {
	Timestamp  time.Time   `json:"timestamp"`
	Command    string      `json:"command"`
	ServerInfo *ServerInfo `json:"serverInfo,omitempty"`
	Tools      []Tool      `json:"tools"`
	Resources  []Resource  `json:"resources"`
	Error      string      `json:"error,omitempty"`
}

// MCPInitializeRequest jsonrpc
type MCPInitializeRequest struct {
	JSONRPC string              `json:"jsonrpc"`
	ID      int                 `json:"id"`
	Method  string              `json:"method"`
	Params  MCPInitializeParams `json:"params"`
}

type MCPInitializeParams struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    MCPCapabilities `json:"capabilities"`
	ClientInfo      MCPClientInfo   `json:"clientInfo"`
}

type MCPCapabilities struct{}

type MCPClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MCPInitializeResponse jsonrpc
type MCPInitializeResponse struct {
	JSONRPC string               `json:"jsonrpc"`
	ID      int                  `json:"id"`
	Result  *MCPInitializeResult `json:"result,omitempty"`
	Error   *MCPError            `json:"error,omitempty"`
}

type MCPInitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	ServerInfo      MCPServerInfo          `json:"serverInfo"`
	Capabilities    map[string]interface{} `json:"capabilities,omitempty"`
}

type MCPServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPListRequest list
type MCPListRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// MCPToolsListResponse list response
type MCPToolsListResponse struct {
	JSONRPC string              `json:"jsonrpc"`
	ID      int                 `json:"id"`
	Result  *MCPToolsListResult `json:"result,omitempty"`
	Error   *MCPError           `json:"error,omitempty"`
}

type MCPToolsListResult struct {
	Tools []MCPTool `json:"tools"`
}

// MCPTool schema
type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
}

// MCPResourcesListResponse list response
type MCPResourcesListResponse struct {
	JSONRPC string                  `json:"jsonrpc"`
	ID      int                     `json:"id"`
	Result  *MCPResourcesListResult `json:"result,omitempty"`
	Error   *MCPError               `json:"error,omitempty"`
}

type MCPResourcesListResult struct {
	Resources []MCPResource `json:"resources"`
}

// MCPResource schema
type MCPResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// MCPNotification msg
type MCPNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}
