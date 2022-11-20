package osquery

import (
	"bytes"
	"context"
	"fmt"

	"github.com/turbot/steampipe-plugin-sdk/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/plugin"
	"github.com/turbot/steampipe-plugin-sdk/plugin/transform"
)

//// TABLE DEFINITION

func tableOSQueryCustom(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_custom",
		Description: "Custom free-form OSQuery query.",
		Columns: []*plugin.Column{
			{
				Name:        "hostname",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the host against which to run the query.",
				Transform:   transform.FromField("Hostname"),
			},
			{
				Name:        "query",
				Type:        proto.ColumnType_STRING,
				Description: "The query to run against the target.",
				Transform:   transform.FromField("Query"),
			},
			{
				Name:        "result",
				Type:        proto.ColumnType_JSON,
				Description: "The result of the query.",
				Transform:   transform.FromField("Result"),
			},
		},
		Get: &plugin.GetConfig{
			Hydrate: getOSQueryCustom,
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "query",
					Require: plugin.Required,
				},
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

//// HYDRATE FUNCTIONS

type result struct {
	Hostname string
	Query    string
	Result   string
}

func getOSQueryCustom(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	setLogLevel(ctx, d)

	hostname := d.KeyColumnQuals["hostname"].GetStringValue()
	query := d.KeyColumnQuals["query"].GetStringValue()
	plugin.Logger(ctx).Debug("running query", "query", query, "hostname", hostname)

	connection, err := getSSHConnection(ctx, d, hostname, false)
	if err != nil {
		plugin.Logger(ctx).Error("error retrieving connection", "error", err)
		return nil, err
	}

	session, err := connection.NewSession()
	if err != nil {
		plugin.Logger(ctx).Error("error creating session", "error", err)
		return nil, err
	}
	defer session.Close()

	var output bytes.Buffer
	session.Stdout = &output
	command := fmt.Sprintf("osqueryi --json \"%s\"", query)
	if err := session.Run(command); err != nil {
		plugin.Logger(ctx).Error("error running query", "command", command, "error", err)
		return nil, err
	}

	// result := users.Get(client, id)
	// var user *users.User
	// user, err = result.Extract()
	// if err != nil {
	// 	plugin.Logger(ctx).Error("error retrieving user", "error", err)
	// 	return nil, err
	// }

	return &result{
		Hostname: hostname,
		Query:    query,
		Result:   output.String(),
	}, nil
}
