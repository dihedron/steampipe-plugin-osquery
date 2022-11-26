package osquery

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hashicorp/go-hclog"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"gopkg.in/yaml.v3"
)

var ErrNotImplemented = errors.New("not implemented")

// setLogLevel changes the current HCLog level; this seems necessary as the
// STEAMPIPE_LOG_LEVEL variable does not seem to be properly read by the plugins.
func setLogLevel(ctx context.Context, d *plugin.QueryData) {
	openstackConfig := GetConfig(d.Connection)
	if openstackConfig.TraceLevel != nil {
		level := *openstackConfig.TraceLevel
		plugin.Logger(ctx).SetLevel(hclog.LevelFromString(level))
	}
}

// toJSON dumps the input object to JSON.
func toJSON(v any) string {
	s, _ := json.Marshal(v)
	return string(s)
}

// toPrettyJSON dumps the input object to JSON.
func toPrettyJSON(v any) string {
	s, _ := json.MarshalIndent(v, "", "  ")
	return string(s)
}

// toYAML dumps the input object to YAML.
func toYAML(v any) string {
	s, _ := yaml.Marshal(v)
	return string(s)
}

// pointerTo returns a pointer to a given value.
func pointerTo[T any](value T) *T {
	return &value
}
