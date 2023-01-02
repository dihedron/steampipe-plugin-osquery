package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOSQueryBlockDevice(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_block_device",
		Description: "The system's block devices.",
		Columns: []*plugin.Column{
			{
				Name:        "hostname",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the host whose block devices are being queried.",
				Transform:   transform.FromField("Hostname"),
			},
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The block device's name.",
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "parent",
				Type:        proto.ColumnType_STRING,
				Description: "The block device's parent device.",
				Transform:   transform.FromField("Parent"),
			},
			{
				Name:        "vendor",
				Type:        proto.ColumnType_STRING,
				Description: "The block device's vendor.",
				Transform:   transform.FromField("Vendor"),
			},
			{
				Name:        "model",
				Type:        proto.ColumnType_STRING,
				Description: "The block device's model.",
				Transform:   transform.FromField("Model"),
			},
			{
				Name:        "size",
				Type:        proto.ColumnType_INT,
				Description: "The block device's size.",
				Transform:   transform.FromField("Size").Transform(SafeInt(0)),
			},
			{
				Name:        "block_size",
				Type:        proto.ColumnType_INT,
				Description: "The block device's block size.",
				Transform:   transform.FromField("BlockSize").Transform(SafeInt(0)),
			},
			{
				Name:        "uuid",
				Type:        proto.ColumnType_STRING,
				Description: "The block device's UUID.",
				Transform:   transform.FromField("UUID"),
			},
			{
				Name:        "type",
				Type:        proto.ColumnType_STRING,
				Description: "The block device's type.",
				Transform:   transform.FromField("Type"),
			},
			{
				Name:        "label",
				Type:        proto.ColumnType_STRING,
				Description: "The block device's lable.",
				Transform:   transform.FromField("Label"),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: makeListOSQuery[*osQueryBlockDevice]("select * from block_devices;"),
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

type osQueryBlockDevice struct {
	Result
	Name      string `json:"name"`
	Parent    string `json:"parent"`
	Vendor    string `json:"vendor"`
	Model     string `json:"model"`
	Size      string `json:"size"`
	BlockSize string `json:"block_size"`
	UUID      string `json:"uuid"`
	Type      string `json:"type"`
	Label     string `json:"label"`
}
