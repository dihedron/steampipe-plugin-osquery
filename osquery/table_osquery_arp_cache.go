package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOSQueryArpCache(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_arp_cache",
		Description: "The ARP cache.",
		Columns: []*plugin.Column{
			{
				Name:        "hostname",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the host whose ARP cache is being queried.",
				Transform:   transform.FromField("Hostname"),
			},
			{
				Name:        "address",
				Type:        proto.ColumnType_STRING,
				Description: "The IP address in the ARP cache.",
				Transform:   transform.FromField("Address"),
			},
			{
				Name:        "mac",
				Type:        proto.ColumnType_STRING,
				Description: "The MAC address in the ARP cache.",
				Transform:   transform.FromField("MAC"),
			},
			{
				Name:        "interface",
				Type:        proto.ColumnType_STRING,
				Description: "The network interface.",
				Transform:   transform.FromField("Interface"),
			},
			{
				Name:        "permanent",
				Type:        proto.ColumnType_STRING,
				Description: "Whether the ARP cache entry is permanent.",
				Transform:   transform.FromField("Permanent"),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: makeListOSQuery[*osQueryArpCache]("select * from arp_cache;"),
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

type osQueryArpCache struct {
	Result
	Address   string `json:"address"`
	MAC       string `json:"mac"`
	Interface string `json:"interface"`
	Permanent string `json:"permanent"`
}
