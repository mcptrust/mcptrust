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
	Tools     map[string]interface{} `json:"tools,omitempty"`
	Prompts   map[string]interface{} `json:"prompts,omitempty"`
	Resources map[string]interface{} `json:"resources,omitempty"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
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

type ResourceTemplate struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// safe_tool (allowed), debug_exec (extra)
var mockTools = []Tool{
	{
		Name:        "safe_tool",
		Description: "A safe tool for testing",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"input": {
					Type:        "string",
					Description: "Input value",
				},
			},
			Required: []string{"input"},
		},
	},
	{
		Name:        "debug_exec",
		Description: "DANGEROUS: Execute arbitrary commands",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"command": {
					Type:        "string",
					Description: "Command to execute",
				},
			},
			Required: []string{"command"},
		},
	},
}

// safe_prompt (allowed), evil_prompt (extra)
var mockPrompts = []Prompt{
	{
		Name:        "safe_prompt",
		Description: "A safe prompt for testing",
		Arguments: []PromptArgument{
			{Name: "topic", Description: "Topic to discuss", Required: true},
		},
	},
	{
		Name:        "evil_prompt",
		Description: "A malicious prompt that should be filtered",
	},
}

// db://{id} (allowed), file:///{path} (extra)
var mockResourceTemplates = []ResourceTemplate{
	{
		URITemplate: "db://{id}",
		Name:        "Database Records",
		Description: "Access database records by ID",
		MimeType:    "application/json",
	},
	{
		URITemplate: "file:///{path}",
		Name:        "File System",
		Description: "Access local files",
		MimeType:    "application/octet-stream",
	},
}

// for --allow-static-resources
var mockStaticResources = []Resource{
	{
		URI:         "static://config.json",
		Name:        "Config File",
		Description: "Application configuration",
		MimeType:    "application/json",
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
					Tools:     map[string]interface{}{},
					Prompts:   map[string]interface{}{},
					Resources: map[string]interface{}{},
				},
				ServerInfo: ServerInfo{
					Name:    "mock-proxy-server",
					Version: "1.0.0",
				},
			},
		}

	case "notifications/initialized":
		return JSONRPCResponse{}

	case "tools/list":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]interface{}{"tools": mockTools},
		}

	case "tools/call":
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &RPCError{Code: -32602, Message: "Invalid params"},
			}
		}
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"content": []map[string]interface{}{
					{
						"type": "text",
						"text": fmt.Sprintf("Executed tool %s with args %v", params.Name, params.Arguments),
					},
				},
			},
		}

	case "prompts/list":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]interface{}{"prompts": mockPrompts},
		}

	case "prompts/get":
		var params struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &RPCError{Code: -32602, Message: "Invalid params"},
			}
		}
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"description": fmt.Sprintf("Prompt: %s", params.Name),
				"messages": []map[string]interface{}{
					{
						"role": "user",
						"content": map[string]interface{}{
							"type": "text",
							"text": fmt.Sprintf("Prompt %s invoked with %v", params.Name, params.Arguments),
						},
					},
				},
			},
		}

	case "resources/templates/list":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]interface{}{"resourceTemplates": mockResourceTemplates},
		}

	case "resources/list":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]interface{}{"resources": mockStaticResources},
		}

	case "resources/read":
		var params struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &RPCError{Code: -32602, Message: "Invalid params"},
			}
		}
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"contents": []map[string]interface{}{
					{
						"uri":      params.URI,
						"mimeType": "text/plain",
						"text":     fmt.Sprintf("Content of %s", params.URI),
					},
				},
			},
		}

	default:
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &RPCError{Code: -32601, Message: fmt.Sprintf("Method not found: %s", req.Method)},
		}
	}
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			errResp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error:   &RPCError{Code: -32700, Message: "Parse error"},
			}
			respBytes, _ := json.Marshal(errResp)
			fmt.Println(string(respBytes))
			continue
		}

		resp := handleRequest(req)

		// Skip response for notifications
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
