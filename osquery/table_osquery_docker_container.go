package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOSQueryDockerContainer(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_docker_container",
		Description: "List of machine Docker containers.",
		Columns: []*plugin.Column{
			{
				Name:        "hostname",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the host on which the process is running.",
				Transform:   transform.FromField("Hostname"),
			},

			{
				Name:        "id",
				Type:        proto.ColumnType_STRING,
				Description: "The container ID.",
				Transform:   transform.FromField("ID"),
			},
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The container name.",
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "image",
				Type:        proto.ColumnType_STRING,
				Description: "The container image.",
				Transform:   transform.FromField("Image"),
			},
			{
				Name:        "image_id",
				Type:        proto.ColumnType_STRING,
				Description: "The container image ID.",
				Transform:   transform.FromField("ImageID"),
			},
			{
				Name:        "command",
				Type:        proto.ColumnType_STRING,
				Description: "The container command.",
				Transform:   transform.FromField("Command"),
			},
			{
				Name:        "created_at_unix",
				Type:        proto.ColumnType_INT,
				Description: "The container creation time (as seconds from Epoch).",
				Transform:   transform.FromField("Created"),
			},
			{
				Name:        "created_at_date",
				Type:        proto.ColumnType_STRING,
				Description: "The container creation time (as a date).",
				Transform:   transform.FromField("Created").Transform(EpochToDate),
			},
			{
				Name:        "state",
				Type:        proto.ColumnType_STRING,
				Description: "The container state.",
				Transform:   transform.FromField("State"),
			},
			{
				Name:        "status",
				Type:        proto.ColumnType_STRING,
				Description: "The container status.",
				Transform:   transform.FromField("Status"),
			},
			{
				Name:        "pid",
				Type:        proto.ColumnType_INT,
				Description: "The container PID.",
				Transform:   transform.FromField("PID"),
			},
			{
				Name:        "path",
				Type:        proto.ColumnType_STRING,
				Description: "The container path.",
				Transform:   transform.FromField("Path"),
			},
			{
				Name:        "config_entrypoint",
				Type:        proto.ColumnType_STRING,
				Description: "The container configuration entrypoint.",
				Transform:   transform.FromField("ConfigEntryPoint"),
			},
			{
				Name:        "started_at",
				Type:        proto.ColumnType_STRING,
				Description: "The container start time.",
				Transform:   transform.FromField("StartedAt"),
			},
			{
				Name:        "finished_at",
				Type:        proto.ColumnType_STRING,
				Description: "The container finish time.",
				Transform:   transform.FromField("FinishedAt"),
			},
			{
				Name:        "privileged",
				Type:        proto.ColumnType_INT,
				Description: "The container privileged status.",
				Transform:   transform.FromField("Privileged"),
			},
			{
				Name:        "security_options",
				Type:        proto.ColumnType_STRING,
				Description: "The container security options.",
				Transform:   transform.FromField("SecurityOptions"),
			},
			{
				Name:        "env_variables",
				Type:        proto.ColumnType_STRING,
				Description: "The container environment variables.",
				Transform:   transform.FromField("EnvVariables"),
			},
			{
				Name:        "readonly_rootfs",
				Type:        proto.ColumnType_STRING,
				Description: "The container read-only root filesystem.",
				Transform:   transform.FromField("ReadOnlyRootFS"),
			},
			{
				Name:        "cgroup_namespace",
				Type:        proto.ColumnType_STRING,
				Description: "The CGroups namespace of the container.",
				Transform:   transform.FromField("CGroupNamespace"),
			},
			{
				Name:        "ipc_namespace",
				Type:        proto.ColumnType_STRING,
				Description: "The IPC namespace of the container.",
				Transform:   transform.FromField("IPCNamespace"),
			},
			{
				Name:        "mnt_namespace",
				Type:        proto.ColumnType_STRING,
				Description: "The Mount namespace of the container.",
				Transform:   transform.FromField("MNTNamespace"),
			},
			{
				Name:        "net_namespace",
				Type:        proto.ColumnType_STRING,
				Description: "The Net namespace of the container.",
				Transform:   transform.FromField("NetNamespace"),
			},
			{
				Name:        "pid_namespace",
				Type:        proto.ColumnType_STRING,
				Description: "The PID namespace of the container.",
				Transform:   transform.FromField("PIDNamespace"),
			},
			{
				Name:        "user_namespace",
				Type:        proto.ColumnType_STRING,
				Description: "The User namespace of the container.",
				Transform:   transform.FromField("UserNamespace"),
			},
			{
				Name:        "uts_namespace",
				Type:        proto.ColumnType_STRING,
				Description: "The UTS namespace of the container.",
				Transform:   transform.FromField("UTSNamespace"),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: makeListOSQuery[*osQueryDockerContainer]("select * from docker_containers;"),
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

type osQueryDockerContainer struct {
	Hostname         string `json:"hostname"`
	ID               string `json:"id"`
	Name             string `json:"name"`
	Image            string `json:"image"`
	ImageID          string `json:"image_id"`
	Command          string `json:"command"`
	Created          string `json:"created"`
	State            string `json:"state"`
	Status           string `json:"status"`
	PID              string `json:"pid"`
	Path             string `json:"path"`
	ConfigEntryPoint string `json:"config_entrypoint"`
	StartedAt        string `json:"started_at"`
	FinishedAt       string `json:"finished_at"`
	Privileged       string `json:"privileged"`
	SecurityOptions  string `json:"security_options"`
	EnvVariables     string `json:"env_variables"`
	ReadOnlyRootFS   string `json:"readonly_rootfs"`
	CGroupNamespace  string `json:"cgroup_namespace"`
	IPCNamespace     string `json:"ipc_namespace"`
	MNTNamespace     string `json:"mnt_namespace"`
	NetNamespace     string `json:"net_namespace"`
	PIDNamespace     string `json:"pid_namespace"`
	UserNamespace    string `json:"user_namespace"`
	UTSNamespace     string `json:"uts_namespace"`
}

func (o *osQueryDockerContainer) SetHostName(hostname string) {
	o.Hostname = hostname
}
