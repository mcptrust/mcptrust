package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
}

type Capabilities struct {
	Tools map[string]interface{} `json:"tools,omitempty"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties,omitempty"`
	Required   []string            `json:"required,omitempty"`
}

type Property struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
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

type PromptsListResult struct {
	Prompts []Prompt `json:"prompts"`
}

type ResourceTemplate struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type ResourceTemplatesListResult struct {
	ResourceTemplates []ResourceTemplate `json:"resourceTemplates"`
}

var mockTools = []Tool{
	{
		Name:        "read_file",
		Description: "Read the complete contents of a file from the file system.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {
					Type:        "string",
					Description: "Absolute path to the file to read",
				},
			},
			Required: []string{"path"},
		},
	},
	{
		Name:        "write_file",
		Description: "Write content to a file, creating it if it doesn't exist.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {
					Type:        "string",
					Description: "Absolute path to the file to write",
				},
				"content": {
					Type:        "string",
					Description: "Content to write to the file",
				},
			},
			Required: []string{"path", "content"},
		},
	},
	{
		Name:        "list_directory",
		Description: "List the contents of a directory.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {
					Type:        "string",
					Description: "Absolute path to the directory to list",
				},
			},
			Required: []string{"path"},
		},
	},
}

var mockPrompts = []Prompt{
	{
		Name:        "code_review",
		Description: "Analyze code quality and suggest improvements",
		Arguments: []PromptArgument{
			{Name: "code", Description: "Code to review", Required: true},
		},
	},
	{
		Name:        "summarize",
		Description: "Summarize the given text",
	},
}

var mockResourceTemplates = []ResourceTemplate{
	{
		URITemplate: "file:///{path}",
		Name:        "Project Files",
		Description: "Access files in the project directory",
		MimeType:    "application/octet-stream",
	},
}

func handleRequest(req JSONRPCRequest) JSONRPCResponse {
	switch req.Method {
	case "initialize":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: InitializeResult{
				ProtocolVersion: "2024-11-05",
				Capabilities: Capabilities{
					Tools: map[string]interface{}{},
				},
				ServerInfo: ServerInfo{
					Name:    "mock-mcp-server",
					Version: "1.0.0",
				},
			},
		}

	case "notifications/initialized":
		// No response needed for notifications
		return JSONRPCResponse{}

	case "tools/list":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: ToolsListResult{
				Tools: mockTools,
			},
		}

	case "resources/list":
		// Return empty list (no static resources)
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"resources": []interface{}{},
			},
		}

	case "prompts/list":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: PromptsListResult{
				Prompts: mockPrompts,
			},
		}

	case "resources/templates/list":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: ResourceTemplatesListResult{
				ResourceTemplates: mockResourceTemplates,
			},
		}

	// forbidden in scan path
	case "resources/read", "prompts/get":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &RPCError{
				Code:    -32600,
				Message: fmt.Sprintf("GUARDRAIL VIOLATION: %s is forbidden in scan path", req.Method),
			},
		}

	default:
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &RPCError{
				Code:    -32601,
				Message: fmt.Sprintf("Method not found: %s", req.Method),
			},
		}
	}
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	// Increase buffer size for larger messages
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			// Send parse error
			errResp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error: &RPCError{
					Code:    -32700,
					Message: "Parse error",
				},
			}
			respBytes, _ := json.Marshal(errResp)
			fmt.Println(string(respBytes))
			continue
		}

		resp := handleRequest(req)

		// Don't send response for notifications (no ID)
		if req.ID == nil && req.Method == "notifications/initialized" {
			continue
		}

		respBytes, err := json.Marshal(resp)
		if err != nil {
			continue
		}
		fmt.Println(string(respBytes))
	}
}
