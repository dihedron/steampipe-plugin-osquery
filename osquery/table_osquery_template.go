package osquery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

type OSQueryResult interface {
	SetHostName(hostname string)
}

func makeListOSQuery[T OSQueryResult](query string) func(context.Context, *plugin.QueryData, *plugin.HydrateData) (interface{}, error) {

	return func(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {
		setLogLevel(ctx, d)

		hostname := d.EqualsQuals["hostname"].GetStringValue()
		plugin.Logger(ctx).Debug("retrieving list of items", "hostname", hostname)

		connection, err := getSSHConnection(ctx, d, hostname, false)
		if err != nil {
			plugin.Logger(ctx).Error("error retrieving connection", "error", err)
			return nil, err
		}

		plugin.Logger(ctx).Debug("connection retrieved")

		session, err := connection.NewSession()
		if err != nil {
			plugin.Logger(ctx).Error("error creating session", "error", err)
			return nil, err
		}
		defer session.Close()

		plugin.Logger(ctx).Debug("session open")

		var output bytes.Buffer
		session.Stdout = &output
		command := fmt.Sprintf("osqueryi --json \"%s\"", query)
		if err := session.Run(command); err != nil {
			plugin.Logger(ctx).Error("error running query", "command", command, "error", err)
			return nil, err
		}

		plugin.Logger(ctx).Debug("command run")

		items := []T{}
		if err = json.Unmarshal(output.Bytes(), &items); err != nil {
			plugin.Logger(ctx).Error("error unmarshalling query result", "error", err)
			return nil, err
		}

		for _, item := range items {
			item.SetHostName(hostname)
			plugin.Logger(ctx).Debug("streaming items", "data", toPrettyJSON(item))
			d.StreamListItem(ctx, item)
		}
		return nil, nil
	}
}
