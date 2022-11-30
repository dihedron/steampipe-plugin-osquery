package osquery

import (
	"context"
	"errors"

	"github.com/hashicorp/go-hclog"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
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
