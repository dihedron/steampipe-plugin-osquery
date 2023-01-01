package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOSQueryAcpiTable(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_acpi_table",
		Description: "List of machine ACPI tables.",
		Columns: []*plugin.Column{
			{
				Name:        "hostname",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the host whose ACPI table are being accessed.",
				Transform:   transform.FromField("Hostname"),
			},
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The ACPI table name.",
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "size",
				Type:        proto.ColumnType_INT,
				Description: "The ACPI table size.",
				Transform:   transform.FromField("size").Transform(SafeInt(-1)),
			},
			{
				Name:        "md5",
				Type:        proto.ColumnType_STRING,
				Description: "The ACPI table's MD5 sum.",
				Transform:   transform.FromField("md5"),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: makeListOSQuery[*osQueryAcpiTable]("select * from acpi_tables;"),
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

type osQueryAcpiTable struct {
	Result
	Name string `json:"name"`
	Size string `json:"size"`
	Md5  string `json:"md5"`
}
