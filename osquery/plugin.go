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
			"osquery_arp_cache":        tableOSQueryArpCache(ctx),
			"osquery_augeas":           tableOSQueryAugeas(ctx),
			"osquery_authorized_key":   tableOSQueryAuthorizedKey(ctx),
			// "osquery_azure_instance_metadata": tableOSQueryAzureInstanceMetadata(ctx),
			// "osquery_azure_instance_tag":      tableOSQueryAzureInstanceTag(ctx),
			"osquery_block_device": tableOSQueryBlockDevice(ctx),
			// "osquery_bpf_process_event": tableOSQueryBpfProcessEvent(ctx),
			// "osquery_bpf_socket_event":  tableOSQueryBpfSocketEvent(ctx),
			// "osquery_carbon_black_info": tableOSQueryCarbonBlackInfo(ctx),
			// "osquery_carve":             tableOSQueryCarve(ctx),
			"osquery_certificate": tableOSQueryCertificate(ctx),
			// => chrome_extension_content_scripts
			// => chrome_extensions
			// => cpu_info
			// => cpu_time
			// => cpuid
			// => crontab
			// => curl
			// => curl_certificate
			// => deb_packages
			// => device_file
			// => device_hash
			// => device_partitions
			// => disk_encryption
			// => dns_resolvers

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
