package config

// Credentials is the effective enterprise destination, shared by telemetry and
// container lifecycle reporting. Non-placeholder build values take precedence.
type Credentials struct{ CustomerID, APIEndpoint, APIKey string }

func EffectiveCredentials(cfg ConfigFile) Credentials {
	choose := func(embedded, stored string) string {
		if embedded != "" && !isPlaceholder(embedded) {
			return embedded
		}
		if !isPlaceholder(stored) {
			return stored
		}
		return ""
	}
	endpoint := APIEndpoint
	// Load normalizes file endpoints but preserves embedded values verbatim.
	if endpoint == "" || isPlaceholder(endpoint) {
		endpoint = NormalizeAPIEndpoint(choose("", cfg.APIEndpoint))
	}
	return Credentials{choose(CustomerID, cfg.CustomerID), endpoint, choose(APIKey, cfg.APIKey)}
}
