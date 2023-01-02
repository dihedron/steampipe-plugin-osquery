package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOSQueryAptSource(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_apt_source",
		Description: "List of Apt sources.",
		Columns: []*plugin.Column{
			{
				Name:        "hostname",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the host whose Apt sources are being queried.",
				Transform:   transform.FromField("Hostname"),
			},
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the Apt source.",
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "source",
				Type:        proto.ColumnType_STRING,
				Description: "The Apt source.",
				Transform:   transform.FromField("Source"),
			},
			{
				Name:        "base_uri",
				Type:        proto.ColumnType_STRING,
				Description: "The Apt base URI.",
				Transform:   transform.FromField("BaseURI"),
			},
			{
				Name:        "release",
				Type:        proto.ColumnType_STRING,
				Description: "The Apt release.",
				Transform:   transform.FromField("Release"),
			},
			{
				Name:        "version",
				Type:        proto.ColumnType_STRING,
				Description: "The Apt version.",
				Transform:   transform.FromField("Version"),
			},
			{
				Name:        "maintainer",
				Type:        proto.ColumnType_STRING,
				Description: "The Apt source maintainer.",
				Transform:   transform.FromField("Maintainer"),
			},
			{
				Name:        "components",
				Type:        proto.ColumnType_STRING,
				Description: "The Apt source components.",
				Transform:   transform.FromField("Components"),
			},
			{
				Name:        "architectures",
				Type:        proto.ColumnType_STRING,
				Description: "The Apt source architectures.",
				Transform:   transform.FromField("Architectures"),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: makeListOSQuery[*osQueryAptSource]("select * from apt_sources;"),
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

type osQueryAptSource struct {
	Result
	Name          string `json:"name"`
	Source        string `json:"source"`
	BaseURI       string `json:"base_uri"`
	Release       string `json:"release"`
	Version       string `json:"version"`
	Maintainer    string `json:"maintainer"`
	Components    string `json:"components"`
	Architectures string `json:"architectures"`
}
