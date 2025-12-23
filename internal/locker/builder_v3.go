package locker

import (
	"sort"
	"time"

	"github.com/mcptrust/mcptrust/internal/models"
	"github.com/mcptrust/mcptrust/internal/version"
)

// BuilderV3 factory
type BuilderV3 struct {
	// TimeFunc allows injecting a time function for testing. Defaults to time.Now.
	TimeFunc func() time.Time
}

// NewBuilderV3 constructor
func NewBuilderV3() *BuilderV3 {
	return &BuilderV3{
		TimeFunc: time.Now,
	}
}

// Build v3 lockfile
func (b *BuilderV3) Build(report *models.ScanReport) (*models.LockfileV3, error) {
	prompts, err := b.buildPrompts(report.Prompts)
	if err != nil {
		return nil, err
	}

	resources, err := b.buildTemplates(report.ResourceTemplates)
	if err != nil {
		return nil, err
	}

	tools, err := b.buildTools(report.Tools)
	if err != nil {
		return nil, err
	}

	serverName := ""
	if report.ServerInfo != nil {
		serverName = report.ServerInfo.Name
	}

	now := b.TimeFunc
	if now == nil {
		now = time.Now
	}

	lockfile := &models.LockfileV3{
		LockFileVersion: models.LockfileV3Version,
		Meta: models.LockfileMeta{
			Generator: "mcptrust " + version.BuildVersion(),
			UpdatedAt: now().UTC().Format(time.RFC3339),
		},
		Server: models.LockfileServer{
			Name: serverName,
		},
		Prompts:   prompts,
		Resources: resources,
		Tools:     tools,
	}

	return lockfile, nil
}

// buildPrompts helper
func (b *BuilderV3) buildPrompts(prompts []models.Prompt) (models.PromptsSection, error) {
	definitions := make(map[string]models.PromptDefinition)

	for _, prompt := range prompts {
		argsHash, err := HashPromptArguments(prompt.Arguments)
		if err != nil {
			return models.PromptsSection{}, err
		}

		def := models.PromptDefinition{
			ArgumentsHash: argsHash,
		}

		// Include optional hashes if content present
		if prompt.Description != "" {
			def.DescriptionHash = HashNormalizedString(prompt.Description)
		}

		definitions[prompt.Name] = def
	}

	return models.PromptsSection{Definitions: definitions}, nil
}

// buildTemplates helper
func (b *BuilderV3) buildTemplates(templates []models.ResourceTemplate) (models.ResourcesSection, error) {
	locks := make([]models.ResourceTemplateLock, 0, len(templates))

	for _, tmpl := range templates {
		templateHash, err := HashTemplate(tmpl.URITemplate, tmpl.MimeType)
		if err != nil {
			return models.ResourcesSection{}, err
		}

		lock := models.ResourceTemplateLock{
			URITemplate:  tmpl.URITemplate,
			TemplateHash: templateHash,
			MimeType:     tmpl.MimeType,
		}

		// Include optional hashes if content present
		if tmpl.Name != "" {
			lock.NameHash = HashNormalizedString(tmpl.Name)
		}
		if tmpl.Description != "" {
			lock.DescriptionHash = HashNormalizedString(tmpl.Description)
		}

		locks = append(locks, lock)
	}

	// Sort by uriTemplate for determinism
	sort.Slice(locks, func(i, j int) bool {
		return locks[i].URITemplate < locks[j].URITemplate
	})

	return models.ResourcesSection{Templates: locks}, nil
}

// buildTools helper
func (b *BuilderV3) buildTools(tools []models.Tool) (map[string]models.ToolLock, error) {
	result := make(map[string]models.ToolLock)

	for _, tool := range tools {
		descHash := HashString(tool.Description)

		schemaHash, err := HashJSON(tool.InputSchema)
		if err != nil {
			return nil, err
		}

		result[tool.Name] = models.ToolLock{
			DescriptionHash: descHash,
			InputSchemaHash: schemaHash,
			RiskLevel:       tool.RiskLevel,
		}
	}

	return result, nil
}

// SetArtifact helper
func (b *BuilderV3) SetArtifact(lockfile *models.LockfileV3, artifact *models.ArtifactPin) {
	lockfile.Server.Artifact = artifact
}
