package model

// ContainerMetadata is explicitly configured workspace attribution.
type ContainerMetadata struct {
	WorkspaceName string `json:"workspace_name,omitempty"`
	RepositoryURL string `json:"repository_url,omitempty"`
	Environment   string `json:"environment,omitempty"`
}

type ContainerLifecycleEvent struct {
	Metadata   *ContainerMetadata `json:"metadata,omitempty"`
	DeviceID   string             `json:"device_id"`
	Event      string             `json:"event"`
	StartID    string             `json:"start_id,omitempty"`
	Hostname   string             `json:"hostname,omitempty"`
	Generation int64              `json:"generation,omitempty"`
	Sequence   int64              `json:"sequence,omitempty"`
}
type ContainerLifecycle struct {
	Metadata         *ContainerMetadata `json:"metadata,omitempty"`
	StartedAt        int64              `json:"started_at,omitempty"`
	StoppedAt        int64              `json:"stopped_at,omitempty"`
	Status           string             `json:"status"`
	Generation       int64              `json:"generation"`
	Sequence         int64              `json:"sequence"`
	LastHeartbeatAt  int64              `json:"last_heartbeat_at"`
	LastTransitionAt int64              `json:"last_transition_at"`
}
type ContainerLifecycleResponse struct {
	Lifecycle ContainerLifecycle `json:"container_lifecycle"`
	Accepted  *bool              `json:"accepted,omitempty"`
}
