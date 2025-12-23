package proxy

// MCPTrustDeniedCode is the JSON-RPC error code for denied requests
const MCPTrustDeniedCode = -32001

// MCPTrustOverloadedCode is the JSON-RPC error code when proxy is at capacity
const MCPTrustOverloadedCode = -32002

// DenyError creates a JSON-RPC error response for denied requests
func DenyError(id interface{}, reason string) map[string]interface{} {
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    MCPTrustDeniedCode,
			"message": "MCPTRUST_DENIED: " + reason,
		},
	}
}

// OverloadedError creates a JSON-RPC error response when proxy is at capacity.
// This is used for fail-closed behavior when we cannot safely register a filter.
func OverloadedError(id interface{}) map[string]interface{} {
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    MCPTrustOverloadedCode,
			"message": "MCPTRUST_OVERLOADED: proxy at capacity, cannot process request safely",
		},
	}
}

// InvalidRequestError creates a JSON-RPC error response for invalid requests.
// SEC-01: Used when hostID validation fails (too large or invalid type).
// Uses standard JSON-RPC error code -32600 (Invalid Request).
func InvalidRequestError(id interface{}, reason string) map[string]interface{} {
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]interface{}{
			"code":    -32600, // JSON-RPC Invalid Request
			"message": "Invalid Request: " + reason,
		},
	}
}
