package models

import "time"

type RiskLevel string

const (
	RiskLevelLow    RiskLevel = "LOW"
	RiskLevelMedium RiskLevel = "MEDIUM"
	RiskLevelHigh   RiskLevel = "HIGH"
)

type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
	RiskLevel   RiskLevel              `json:"riskLevel"`
	RiskReasons []string               `json:"riskReasons,omitempty"`
}

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

type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type ResourceTemplate struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type ScanReport struct {
	Timestamp         time.Time          `json:"timestamp"`
	Command           string             `json:"command"`
	ServerInfo        *ServerInfo        `json:"serverInfo,omitempty"`
	Tools             []Tool             `json:"tools"`
	Resources         []Resource         `json:"resources"`
	Prompts           []Prompt           `json:"prompts"`
	ResourceTemplates []ResourceTemplate `json:"resourceTemplates"`
	Error             string             `json:"error,omitempty"`
}

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

type MCPListRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      int            `json:"id"`
	Method  string         `json:"method"`
	Params  *MCPListParams `json:"params,omitempty"`
}

type MCPListParams struct {
	Cursor string `json:"cursor,omitempty"`
}

type MCPToolsListResponse struct {
	JSONRPC string              `json:"jsonrpc"`
	ID      int                 `json:"id"`
	Result  *MCPToolsListResult `json:"result,omitempty"`
	Error   *MCPError           `json:"error,omitempty"`
}

type MCPToolsListResult struct {
	Tools []MCPTool `json:"tools"`
}

type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
}

type MCPResourcesListResponse struct {
	JSONRPC string                  `json:"jsonrpc"`
	ID      int                     `json:"id"`
	Result  *MCPResourcesListResult `json:"result,omitempty"`
	Error   *MCPError               `json:"error,omitempty"`
}

type MCPResourcesListResult struct {
	Resources []MCPResource `json:"resources"`
}

type MCPResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type MCPNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type MCPPromptsListResponse struct {
	JSONRPC string                `json:"jsonrpc"`
	ID      int                   `json:"id"`
	Result  *MCPPromptsListResult `json:"result,omitempty"`
	Error   *MCPError             `json:"error,omitempty"`
}

type MCPPromptsListResult struct {
	Prompts    []Prompt `json:"prompts"`
	NextCursor string   `json:"nextCursor,omitempty"`
}

type MCPResourceTemplatesListResponse struct {
	JSONRPC string                          `json:"jsonrpc"`
	ID      int                             `json:"id"`
	Result  *MCPResourceTemplatesListResult `json:"result,omitempty"`
	Error   *MCPError                       `json:"error,omitempty"`
}

type MCPResourceTemplatesListResult struct {
	ResourceTemplates []ResourceTemplate `json:"resourceTemplates"`
	NextCursor        string             `json:"nextCursor,omitempty"`
}

const (
	JSONRPCMethodNotFound = -32601
)
