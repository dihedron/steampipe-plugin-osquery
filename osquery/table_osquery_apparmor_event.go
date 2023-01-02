package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOSQueryAppArmorEvent(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_apparmor_event",
		Description: "List of AppArmor events.",
		Columns: []*plugin.Column{
			{
				Name:        "hostname",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the host on which the process is running.",
				Transform:   transform.FromField("Hostname"),
			},
			{
				Name:        "pid",
				Type:        proto.ColumnType_INT,
				Description: "The PID of the process related to the AppArmor event.",
				Transform:   transform.FromField("PID"),
			},
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the AppArmor event.",
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "type",
				Type:        proto.ColumnType_STRING,
				Description: "The tytpe of event.",
				Transform:   transform.FromField("Type"),
			},
			{
				Name:        "message",
				Type:        proto.ColumnType_STRING,
				Description: "The message associated with the AppArmor event.",
				Transform:   transform.FromField("Message"),
			},
			{
				Name:        "time",
				Type:        proto.ColumnType_INT,
				Description: "The AppArmor event's time.",
				Transform:   transform.FromField("Time"),
			},
			{
				Name:        "uptime",
				Type:        proto.ColumnType_INT,
				Description: "The AppArmor event's uptime.",
				Transform:   transform.FromField("UpTime"),
			},
			{
				Name:        "eid",
				Type:        proto.ColumnType_INT,
				Description: "The AppArmor event ID.",
				Transform:   transform.FromField("EID"),
			},
			{
				Name:        "apparmor",
				Type:        proto.ColumnType_STRING,
				Description: "AppArmor.",
				Transform:   transform.FromField("AppArmor"),
			},
			{
				Name:        "operation",
				Type:        proto.ColumnType_STRING,
				Description: "The AppArmor event's operation.",
				Transform:   transform.FromField("Operation"),
			},
			{
				Name:        "parent",
				Type:        proto.ColumnType_INT,
				Description: "The AppArmor event's parent.",
				Transform:   transform.FromField("Parent"),
			},
			{
				Name:        "profile",
				Type:        proto.ColumnType_STRING,
				Description: "The AppArmor profile.",
				Transform:   transform.FromField("Profile"),
			},
			{
				Name:        "comm",
				Type:        proto.ColumnType_STRING,
				Description: "The AppArmor event's comm.",
				Transform:   transform.FromField("Comm"),
			},
			{
				Name:        "requested_mask",
				Type:        proto.ColumnType_STRING,
				Description: "The AppArmor Requested Mask value.",
				Transform:   transform.FromField("RequestedMask"),
			},
			{
				Name:        "denied_mask",
				Type:        proto.ColumnType_STRING,
				Description: "The AppArmor Denied Mask value.",
				Transform:   transform.FromField("DeniedMask"),
			},
			{
				Name:        "capname",
				Type:        proto.ColumnType_STRING,
				Description: "The AppArmor capability name.",
				Transform:   transform.FromField("CapName"),
			},
			{
				Name:        "capability",
				Type:        proto.ColumnType_INT,
				Description: "The AppArmor capability.",
				Transform:   transform.FromField("Capability").Transform(SafeInt(-1)),
			},
			{
				Name:        "info",
				Type:        proto.ColumnType_STRING,
				Description: "The AppArmor event info.",
				Transform:   transform.FromField("Info"),
			},
			{
				Name:        "error",
				Type:        proto.ColumnType_STRING,
				Description: "The AppArmor event error.",
				Transform:   transform.FromField("Error"),
			},
			{
				Name:        "namespace",
				Type:        proto.ColumnType_STRING,
				Description: "The AppArmor event's namespace.",
				Transform:   transform.FromField("Namespace"),
			},
			{
				Name:        "label",
				Type:        proto.ColumnType_STRING,
				Description: "The AppArmor event's label.",
				Transform:   transform.FromField("Label"),
			},
			{
				Name:        "fsuid",
				Type:        proto.ColumnType_INT,
				Description: "The AppArmor FSUID.",
				Transform:   transform.FromField("FSUID"),
			},
			{
				Name:        "ouid",
				Type:        proto.ColumnType_INT,
				Description: "The AppArmor OUID.",
				Transform:   transform.FromField("OUID"),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: makeListOSQuery[*osQueryAppArmorEvent]("select * from apparmor_events;"),
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

type osQueryAppArmorEvent struct {
	Result
	Type          string `json:"type"`
	Message       string `json:"message"`
	Time          string `json:"time"`
	UpTime        string `json:"uptime"`
	EID           string `json:"eid"`
	AppArmor      string `json:"apparmor"`
	Operation     string `json:"operation"`
	Parent        string `json:"parent"`
	Profile       string `json:"profile"`
	Name          string `json:"name"`
	PID           string `json:"pid"`
	Comm          string `json:"comm"`
	DeniedMask    string `json:"denied_mask"`
	CapName       string `json:"capname"`
	FSUID         string `json:"fsuid"`
	OUID          string `json:"ouid"`
	Capability    string `json:"capability"`
	RequestedMash string `json:"requested_mask"`
	Info          string `json:"info"`
	Error         string `json:"error"`
	Namespace     string `json:"namespace"`
	Label         string `json:"label"`
}
