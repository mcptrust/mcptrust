package models

// LockfileV3Version current
const LockfileV3Version = "3.0"

// LockfileMeta metadata
type LockfileMeta struct {
	Generator string `json:"generator"`
	UpdatedAt string `json:"updatedAt"`
}

// LockfileServer identity
type LockfileServer struct {
	Name     string       `json:"name"`
	Artifact *ArtifactPin `json:"artifact,omitempty"`
}

// PromptDefinition hash
type PromptDefinition struct {
	ArgumentsHash   string `json:"argumentsHash"`
	TitleHash       string `json:"titleHash,omitempty"`
	DescriptionHash string `json:"descriptionHash,omitempty"`
}

// ResourceTemplateLock hash
type ResourceTemplateLock struct {
	URITemplate     string `json:"uriTemplate"`
	TemplateHash    string `json:"templateHash"`
	NameHash        string `json:"nameHash,omitempty"`
	DescriptionHash string `json:"descriptionHash,omitempty"`
	MimeType        string `json:"mimeType,omitempty"`
}

// PromptsSection locked
type PromptsSection struct {
	Definitions map[string]PromptDefinition `json:"definitions"`
}

// ResourcesSection locked
type ResourcesSection struct {
	Templates []ResourceTemplateLock `json:"templates"`
}

// LockfileV3 structure
type LockfileV3 struct {
	LockFileVersion string              `json:"lockFileVersion"`
	Meta            LockfileMeta        `json:"meta"`
	Server          LockfileServer      `json:"server"`
	Prompts         PromptsSection      `json:"prompts"`
	Resources       ResourcesSection    `json:"resources"`
	Tools           map[string]ToolLock `json:"tools"`
}
