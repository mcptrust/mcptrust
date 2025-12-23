package differ

// SeverityString to lowercase
func SeverityString(s SeverityLevel) string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityModerate:
		return "moderate"
	case SeveritySafe:
		return "info"
	default:
		return "unknown"
	}
}
