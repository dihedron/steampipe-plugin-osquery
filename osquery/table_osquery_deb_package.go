package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

// // TABLE DEFINITION
func tableOSQueryDebPackage(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_deb_package",
		Description: "List of machine DEB packages.",
		Columns: []*plugin.Column{
			{
				Name:        "hostname",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the host on which the process is running.",
				Transform:   transform.FromField("Hostname"),
			},
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The package name.",
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "version",
				Type:        proto.ColumnType_STRING,
				Description: "The package version.",
				Transform:   transform.FromField("Version"),
			},
			{
				Name:        "source",
				Type:        proto.ColumnType_STRING,
				Description: "The package source.",
				Transform:   transform.FromField("Source"),
			},
			{
				Name:        "size",
				Type:        proto.ColumnType_INT,
				Description: "The size of the package.",
				Transform:   transform.FromField("Size").Transform(SafeInt(0)),
			},
			{
				Name:        "arch",
				Type:        proto.ColumnType_STRING,
				Description: "The package architecture.",
				Transform:   transform.FromField("Arch"),
			},
			{
				Name:        "revision",
				Type:        proto.ColumnType_STRING,
				Description: "The package revision.",
				Transform:   transform.FromField("Revision"), //.Transform(TrimString),
			},
			{
				Name:        "status",
				Type:        proto.ColumnType_STRING,
				Description: "The package status.",
				Transform:   transform.FromField("Status"), //.Transform(TrimString),
			},
			{
				Name:        "maintainer",
				Type:        proto.ColumnType_STRING,
				Description: "The package maintainer.",
				Transform:   transform.FromField("Maintainer"),
			},
			{
				Name:        "section",
				Type:        proto.ColumnType_STRING,
				Description: "The package section.",
				Transform:   transform.FromField("Section"),
			},
			{
				Name:        "priority",
				Type:        proto.ColumnType_STRING,
				Description: "The package priority.",
				Transform:   transform.FromField("Priority"),
			},
			{
				Name:        "admindir",
				Type:        proto.ColumnType_STRING,
				Description: "The package admin directory.",
				Transform:   transform.FromField("AdminDir"),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: makeListOSQuery[*osQueryDebPackage]("select * from deb_packages;"),
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

type osQueryDebPackage struct {
	Result
	Name       string `json:"name"`
	Version    string `json:"version"`
	Source     string `json:"source"`
	Size       string `json:"size"`
	Arch       string `json:"arch"`
	Revision   string `json:"revision"`
	Status     string `json:"status"`
	Maintainer string `json:"maintainer"`
	Section    string `json:"section"`
	Priority   string `json:"priority"`
	AdminDir   string `json:"admindir"`
}
