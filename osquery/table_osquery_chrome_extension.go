package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOSQueryChromeExtension(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_chrome_extension",
		Description: "The system's chrome extensions.",
		Columns: []*plugin.Column{
			{
				Name:        "hostname",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the host whose certificates are being queried.",
				Transform:   transform.FromField("Hostname"),
			},
			{
				Name:        "browser_type",
				Type:        proto.ColumnType_STRING,
				Description: "The type of browser.",
				Transform:   transform.FromField("BrowserType"),
			},
			{
				Name:        "uid",
				Type:        proto.ColumnType_INT,
				Description: "The UID of the user who installed the extension.",
				Transform:   transform.FromField("UID"), //.Transform(SafeInt(-1)),
			},
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's name.",
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "profile",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's profile.",
				Transform:   transform.FromField("Profile"),
			},
			{
				Name:        "profile_path",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's profile path.",
				Transform:   transform.FromField("SelfSigned").Transform(SafeInt(0)),
			},
			{
				Name:        "referenced_identifier",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's referenced identifier.",
				Transform:   transform.FromField("ReferencedIdentifier"),
			},
			{
				Name:        "identifier",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's identifier.",
				Transform:   transform.FromField("Identifier"),
			},
			{
				Name:        "version",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's version.",
				Transform:   transform.FromField("Version"),
			},
			{
				Name:        "description",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's description.",
				Transform:   transform.FromField("Description"),
			},
			{
				Name:        "default_locale",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's default locale.",
				Transform:   transform.FromField("DefaultLocale"),
			},
			{
				Name:        "current_locale",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's current locale.",
				Transform:   transform.FromField("CurrentLocale"),
			},
			{
				Name:        "update_url",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's update URL.",
				Transform:   transform.FromField("UpdateURL"),
			},
			{
				Name:        "author",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's author.",
				Transform:   transform.FromField("Author"),
			},
			{
				Name:        "persistent",
				Type:        proto.ColumnType_INT,
				Description: "Whether the extension is persistent.",
				Transform:   transform.FromField("Persistent"),
			},
			{
				Name:        "path",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's path.",
				Transform:   transform.FromField("Path"),
			},
			{
				Name:        "permissions",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's permissions.",
				Transform:   transform.FromField("Permissions"),
			},
			{
				Name:        "optional_permissions",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's optional permissions.",
				Transform:   transform.FromField("OptionalPermissions"),
			},
			{
				Name:        "manifest_hash",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's manifest hash.",
				Transform:   transform.FromField("ManifestHash"),
			},
			{
				Name:        "referenced",
				Type:        proto.ColumnType_INT,
				Description: "The extension's referenced state.",
				Transform:   transform.FromField("Referenced"),
			},
			{
				Name:        "from_webstore",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's webstore.",
				Transform:   transform.FromField("FromWebstore"),
			},
			{
				Name:        "state",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's state.",
				Transform:   transform.FromField("State"),
			},
			{
				Name:        "install_time",
				Type:        proto.ColumnType_STRING,
				Description: "The extension's install time.",
				Transform:   transform.FromField("InstallTime"),
			},
			{
				Name:        "install_timestamp",
				Type:        proto.ColumnType_INT,
				Description: "The extension's install timestamp.",
				Transform:   transform.FromField("InstallTimestamp"),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: makeListOSQuery[*osQueryChromeExtension]("select * from chrome_extensions;"),
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

type osQueryChromeExtension struct {
	Result
	BrowserType          string `json:"browser_type"`
	UID                  string `json:"uid"`
	Name                 string `json:"name"`
	Profile              string `json:"profile"`
	ProfilePath          string `json:"profile_path"`
	ReferencedIdentifier string `json:"referenced_identifier"`
	Identifier           string `json:"identifier"`
	Version              string `json:"version"`
	Description          string `json:"description"`
	DefaultLocale        string `json:"default_locale"`
	CurrentLocale        string `json:"current_locale"`
	UpdateURL            string `json:"update_url"`
	Author               string `json:"author"`
	Persistent           string `json:"persistent"`
	Path                 string `json:"path"`
	Permissions          string `json:"permissions"`
	OptionalPermissions  string `json:"optional_permissions"`
	ManifestHash         string `json:"manifest_hash"`
	Referenced           string `json:"referenced"`
	FromWebstore         string `json:"from_webstore"`
	State                string `json:"state"`
	InstallTime          string `json:"install_time"`
	InstallTimestamp     string `json:"install_timestamp"`
}
