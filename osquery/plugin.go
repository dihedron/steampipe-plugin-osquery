package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

func Plugin(ctx context.Context) *plugin.Plugin {
	p := &plugin.Plugin{
		Name:             "steampipe-plugin-osquery",
		DefaultTransform: transform.FromGo().NullIfZero(),
		TableMap: map[string]*plugin.Table{
			"osquery_custom":           tableOSQueryCustom(ctx),
			"osquery_acpi_table":       tableOSQueryAcpiTable(ctx),
			"osquery_apparmor_event":   tableOSQueryAppArmorEvent(ctx),
			"osquery_apparmor_profile": tableOSQueryAppArmorProfile(ctx),
			"osquery_apt_source":       tableOSQueryAptSource(ctx),
			"osquery_process":          tableOSQueryProcess(ctx),
			"osquery_deb_package":      tableOSQueryDebPackage(ctx),
			"osquery_rpm_package":      tableOSQueryRpmPackage(ctx),
			"osquery_docker_container": tableOSQueryDockerContainer(ctx),
		},
		ConnectionConfigSchema: &plugin.ConnectionConfigSchema{
			NewInstance: ConfigInstance,
			Schema:      ConfigSchema,
		},
	}
	return p
}
