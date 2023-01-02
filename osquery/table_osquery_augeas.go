package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOSQueryAugeas(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_augeas",
		Description: "The system's augeas configuration tree.",
		Columns: []*plugin.Column{
			{
				Name:        "hostname",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the host whose ARP cache is being queried.",
				Transform:   transform.FromField("Hostname"),
			},
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The augeas entry name.",
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "value",
				Type:        proto.ColumnType_STRING,
				Description: "The augeas entry value.",
				Transform:   transform.FromField("Value"),
			},
			{
				Name:        "label",
				Type:        proto.ColumnType_STRING,
				Description: "The augeas entry label.",
				Transform:   transform.FromField("Label"),
			},
			{
				Name:        "path",
				Type:        proto.ColumnType_STRING,
				Description: "The augeas entry path.",
				Transform:   transform.FromField("Path"),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: makeListOSQuery[*osQueryAugeas]("select * from augeas;"),
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

type osQueryAugeas struct {
	Result
	Name  string `json:"name"`
	Value string `json:"value"`
	Label string `json:"label"`
	Path  string `json:"path"`
}
