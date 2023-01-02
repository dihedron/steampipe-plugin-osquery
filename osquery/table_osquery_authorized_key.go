package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOSQueryAuthorizedKey(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_authorized_key",
		Description: "The system's authorised keys.",
		Columns: []*plugin.Column{
			{
				Name:        "hostname",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the host whose authorised keys are being queried.",
				Transform:   transform.FromField("Hostname"),
			},
			{
				Name:        "uid",
				Type:        proto.ColumnType_INT,
				Description: "The authorised key's UID.",
				Transform:   transform.FromField("UID"),
			},

			{
				Name:        "algorithm",
				Type:        proto.ColumnType_STRING,
				Description: "The authorised key's algorithm.",
				Transform:   transform.FromField("Algorithm"),
			},
			{
				Name:        "key",
				Type:        proto.ColumnType_STRING,
				Description: "The authorised key.",
				Transform:   transform.FromField("Key"),
			},
			{
				Name:        "options",
				Type:        proto.ColumnType_STRING,
				Description: "The authorised key's options.",
				Transform:   transform.FromField("Options"),
			},
			{
				Name:        "path",
				Type:        proto.ColumnType_STRING,
				Description: "The authorised key's comment.",
				Transform:   transform.FromField("Comment"),
			},
			{
				Name:        "key_file",
				Type:        proto.ColumnType_STRING,
				Description: "The authorised key's file.",
				Transform:   transform.FromField("KeyFile"),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: makeListOSQuery[*osQueryAuthorizedKey]("select * from authorized_keys;"),
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

type osQueryAuthorizedKey struct {
	Result
	UID       string `json:"uid"`
	Algorithm string `json:"algorithm"`
	Key       string `json:"key"`
	Options   string `json:"options"`
	Comment   string `json:"comment"`
	KeyFile   string `json:"key_file"`
}
