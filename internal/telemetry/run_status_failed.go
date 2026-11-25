package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/config"
)

const (
	standaloneFailedAttempts = 2
	standaloneFailedTimeout  = 10 * time.Second
)

// PostRunStatusFailed posts a standalone "failed" run-status row under a
// fresh execution id, for work outside a scan run (the on-device firewall
// step of the SYSTEM update tick, say), the way the loaders' Send-RunStatusFailed
// does. errMsg is "<error_type>: <detail>". client carries the proxy settings
// (nil = http.DefaultClient). Two attempts; a 4xx is final. It returns nil
// only when the backend accepted the row.
func PostRunStatusFailed(ctx context.Context, client *http.Client, deviceID, errMsg, invocationMethod string) error {
	if !config.IsEnterpriseMode() {
		return errors.New("not in enterprise mode")
	}
	if deviceID == "" {
		return errors.New("no device id")
	}
	if errMsg == "" {
		errMsg = "unspecified failure"
	}
	if len(errMsg) > runStatusMaxErrorChars {
		errMsg = errMsg[:runStatusMaxErrorChars]
	}
	body, err := json.Marshal(runStatusBody{
		ExecutionID: uuid.NewString(), DeviceID: deviceID, Status: runStatusFailed,
		AgentVersion: buildinfo.Version, Platform: runtime.GOOS,
		InvocationMethod: invocationMethod, ErrorMessage: errMsg,
	})
	if err != nil {
		return err
	}
	if client == nil {
		client = http.DefaultClient
	}
	endpoint := fmt.Sprintf("%s/v1/%s/developer-mdm-agent/telemetry/run-status", config.APIEndpoint, config.CustomerID)
	var last error
	for i := 0; i < standaloneFailedAttempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(runStatusRetryBackoff):
			}
		}
		var final bool
		final, last = postStandaloneOnce(ctx, client, endpoint, body)
		if final {
			return last
		}
	}
	return last
}

// postStandaloneOnce reports final for a 2xx (nil error) or a 4xx.
func postStandaloneOnce(ctx context.Context, client *http.Client, endpoint string, body []byte) (final bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, standaloneFailedTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return true, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+config.APIKey)
	req.Header.Set("X-Agent-Version", buildinfo.Version)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode < 300:
		return true, nil
	case resp.StatusCode < 500:
		return true, fmt.Errorf("run-status: HTTP %d", resp.StatusCode)
	}
	return false, fmt.Errorf("run-status: HTTP %d", resp.StatusCode)
}

// NetErrorCode is the stable "[net_*]" cause code of an http.Client error
// (the set the loaders emit), for run-status messages built outside this
// package.
func NetErrorCode(err error) string { return netErrorCode(err) }

// HTTPStatusCode is the stable cause code of an unexpected HTTP status
// (http_4xx, http_5xx, net_proxy for 407).
func HTTPStatusCode(status int) string { return httpStatusCode(status) }
