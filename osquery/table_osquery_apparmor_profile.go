package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOSQueryAppArmorProfile(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_apparmor_profile",
		Description: "List of AppArmor profiles.",
		Columns: []*plugin.Column{
			{
				Name:        "hostname",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the host on which the process is running.",
				Transform:   transform.FromField("Hostname"),
			},
			{
				Name:        "path",
				Type:        proto.ColumnType_STRING,
				Description: "The path of the AppArmor profile.",
				Transform:   transform.FromField("Path"),
			},
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the AppArmor event.",
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "attach",
				Type:        proto.ColumnType_STRING,
				Description: "The AppArmor profile attach info.",
				Transform:   transform.FromField("Attach"),
			},
			{
				Name:        "mode",
				Type:        proto.ColumnType_STRING,
				Description: "The AppArmor profile mode.",
				Transform:   transform.FromField("Mode"),
			},
			{
				Name:        "sha1",
				Type:        proto.ColumnType_STRING,
				Description: "The AppArmor profile's SHA1 sum.",
				Transform:   transform.FromField("Sha1"),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: makeListOSQuery[*osQueryAppArmorProfile]("select * from apparmor_profiles;"),
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

type osQueryAppArmorProfile struct {
	Result
	Path   string `json:"path"`
	Name   string `json:"name"`
	Attach string `json:"attach"`
	Mode   string `json:"mode"`
	Sha1   string `json:"sha1"`
}
