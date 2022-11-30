package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOSQueryRpmPackage(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_rpm_package",
		Description: "List of machine RPM packages.",
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
				Name:        "release",
				Type:        proto.ColumnType_STRING,
				Description: "The package release.",
				Transform:   transform.FromField("Release"),
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
				Name:        "sha1",
				Type:        proto.ColumnType_STRING,
				Description: "The package SHA1 checksum.",
				Transform:   transform.FromField("SHA1"),
			},
			{
				Name:        "arch",
				Type:        proto.ColumnType_STRING,
				Description: "The package architecture.",
				Transform:   transform.FromField("Arch"),
			},
			{
				Name:        "epoch",
				Type:        proto.ColumnType_STRING,
				Description: "The package epoch.",
				Transform:   transform.FromField("Epoch"), //.Transform(TrimString),
			},
			{
				Name:        "install_time",
				Type:        proto.ColumnType_STRING,
				Description: "The package install time.",
				Transform:   transform.FromField("InstallTime"), //.Transform(TrimString),
			},
			{
				Name:        "vendor",
				Type:        proto.ColumnType_STRING,
				Description: "The package vendor.",
				Transform:   transform.FromField("Vendor"),
			},
			{
				Name:        "package_group",
				Type:        proto.ColumnType_STRING,
				Description: "The package group.",
				Transform:   transform.FromField("PackageGroup"),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: makeListOSQuery[*osQueryRpmPackage]("select * from rpm_packages;"),
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

type osQueryRpmPackage struct {
	Hostname     string `json:"hostname"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Release      string `json:"release"`
	Source       string `json:"source"`
	Size         string `json:"size"`
	SHA1         string `json:"sha1"`
	Arch         string `json:"arch"`
	Epoch        string `json:"epoch"`
	InstallTime  string `json:"install_time"`
	Vendor       string `json:"vendor"`
	PackageGroup string `json:"package_group"`
}

func (o *osQueryRpmPackage) SetHostName(hostname string) {
	o.Hostname = hostname
}
