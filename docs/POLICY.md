# Policy Guide

MCPTrust uses [CEL (Common Expression Language)](https://github.com/google/cel-spec) to define security policies.

## Policy File Structure

A policy file is a YAML document with a list of rules.

```yaml
name: "My Policy"
rules:
  - name: "Rule Name"
    # CEL expression evaluated against 'input'
    expr: "expression" 
    failure_msg: "Message to show if false"
```

## The `input` Object

The `input` variable provides access to the scan report:

| Field | Type | Description |
|-------|------|-------------|
| `input.tools` | list | Tools discovered on server |
| `input.tools[].name` | string | Tool name |
| `input.tools[].description` | string | Tool description |
| `input.tools[].risk_level` | string | `"LOW"`, `"MEDIUM"`, or `"HIGH"` |
| `input.tools[].inputSchema` | map | JSON Schema for tool arguments |

**Fail-closed behavior**: Parse errors, missing fields, or unknown functions cause the policy check to fail.

## Examples

### Safe Starter Policy
Ensures the server exposes at least one tool and no obvious high-risk tools.

```yaml
name: "Safe Starter"
rules:
  - name: "Tools Exist"
    expr: "size(input.tools) > 0"
    failure_msg: "Server is empty."
    
  - name: "No High Risk"
    expr: "!input.tools.exists(t, t.risk_level == 'HIGH')"
    failure_msg: "High-risk tools are not allowed."
```

### Strict Policy (Denylist)
Block known dangerous tools by name.

```yaml
name: "Strict Denylist"
rules:
  - name: "No Dangerous Tools"
    expr: "!input.tools.exists(t, t.name in ['exec', 'shell', 'eval', 'run_command'])"
    failure_msg: "Dangerous tool detected."

  - name: "Approved Prefix"
    expr: "input.tools.all(t, t.name.startsWith('my_service_'))"
    failure_msg: "Tools must be namespaced with 'my_service_'."

  - name: "Argument Limit"
    expr: "input.tools.all(t, size(t.inputSchema.properties) <= 5)"
    failure_msg: "Tools cannot have more than 5 arguments."
```
