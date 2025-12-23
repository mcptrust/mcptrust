package logging

type Config struct {
	Format string
	Level  string
	Output string
}

func DefaultConfig() Config {
	return Config{
		Format: "pretty",
		Level:  "info",
		Output: "stderr",
	}
}

const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

func levelPriority(level string) int {
	switch level {
	case LevelDebug:
		return 0
	case LevelInfo:
		return 1
	case LevelWarn:
		return 2
	case LevelError:
		return 3
	default:
		return 1 // default to info
	}
}
