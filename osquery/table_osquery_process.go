package osquery

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOSQueryProcess(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_process",
		Description: "List of machine processes.",
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
				Description: "The process' PID.",
				Transform:   transform.FromField("PID"),
			},
			{
				Name:        "name",
				Type:        proto.ColumnType_STRING,
				Description: "The process' name.",
				Transform:   transform.FromField("Name"),
			},
			{
				Name:        "path",
				Type:        proto.ColumnType_STRING,
				Description: "The process' path.",
				Transform:   transform.FromField("Path"),
			},
			{
				Name:        "cmdline",
				Type:        proto.ColumnType_STRING,
				Description: "The command line of the process.",
				Transform:   transform.FromField("Cmdline"), //.Transform(TrimString),
			},
			{
				Name:        "state",
				Type:        proto.ColumnType_STRING,
				Description: "The process' state.",
				Transform:   transform.FromField("State"),
			},
			{
				Name:        "cwd",
				Type:        proto.ColumnType_STRING,
				Description: "The working directory of the process.",
				Transform:   transform.FromField("Cwd"), //.Transform(TrimString),
			},
			{
				Name:        "root",
				Type:        proto.ColumnType_STRING,
				Description: "The process' root.",
				Transform:   transform.FromField("Root"),
			},
			{
				Name:        "uid",
				Type:        proto.ColumnType_INT,
				Description: "The process' UID.",
				Transform:   transform.FromField("UID"),
			},
			{
				Name:        "gid",
				Type:        proto.ColumnType_INT,
				Description: "The process' group ID (GID).",
				Transform:   transform.FromField("GID"),
			},
			{
				Name:        "euid",
				Type:        proto.ColumnType_INT,
				Description: "The process' effective user ID (EUID).",
				Transform:   transform.FromField("EUID"),
			},
			{
				Name:        "egid",
				Type:        proto.ColumnType_INT,
				Description: "The process' effective group ID (EGID).",
				Transform:   transform.FromField("EGID"),
			},
			{
				Name:        "suid",
				Type:        proto.ColumnType_INT,
				Description: "The process' SUID.",
				Transform:   transform.FromField("SUID"),
			},
			{
				Name:        "sgid",
				Type:        proto.ColumnType_INT,
				Description: "The process' SGID.",
				Transform:   transform.FromField("SGID"),
			},
			{
				Name:        "on_disk",
				Type:        proto.ColumnType_INT,
				Description: "The process' on disk size value.",
				Transform:   transform.FromField("OnDisk").Transform(SafeInt(-1)),
			},
			{
				Name:        "wired_size",
				Type:        proto.ColumnType_INT,
				Description: "The process' wired size.",
				Transform:   transform.FromField("WiderSize").Transform(SafeInt(-1)),
			},
			{
				Name:        "resident_size",
				Type:        proto.ColumnType_INT,
				Description: "The process' resident size.",
				Transform:   transform.FromField("ResidentSize").Transform(SafeInt(-1)),
			},
			{
				Name:        "total_size",
				Type:        proto.ColumnType_INT,
				Description: "The process' total size.",
				Transform:   transform.FromField("TotalSize").Transform(SafeInt(-1)),
			},
			{
				Name:        "user_time",
				Type:        proto.ColumnType_INT,
				Description: "The process' user time.",
				Transform:   transform.FromField("UserTime"),
			},
			{
				Name:        "system_time",
				Type:        proto.ColumnType_INT,
				Description: "The process' system time.",
				Transform:   transform.FromField("SystemTime"),
			},
			{
				Name:        "disk_bytes_read",
				Type:        proto.ColumnType_INT,
				Description: "The number of disk bytes read by the process.",
				Transform:   transform.FromField("DiskBytesRead").Transform(SafeInt(-1)),
			},
			{
				Name:        "disk_bytes_written",
				Type:        proto.ColumnType_INT,
				Description: "The number of disk bytes writter by the process.",
				Transform:   transform.FromField("DiskBytesWritten").Transform(SafeInt(-1)),
			},
			{
				Name:        "start_time_unix",
				Type:        proto.ColumnType_INT,
				Description: "The process' start time (in seconds since Epoch).",
				Transform:   transform.FromField("StartTime"),
			},
			{
				Name:        "start_time_date",
				Type:        proto.ColumnType_STRING,
				Description: "The process' start time (in date format).",
				Transform:   transform.FromField("StartTime").Transform(EpochToDate),
			},
			{
				Name:        "parent",
				Type:        proto.ColumnType_INT,
				Description: "The process' parent PID.",
				Transform:   transform.FromField("Parent"),
			},
			{
				Name:        "pgroup",
				Type:        proto.ColumnType_INT,
				Description: "The process' process group.",
				Transform:   transform.FromField("Pgroup"),
			},
			{
				Name:        "threads",
				Type:        proto.ColumnType_INT,
				Description: "The process' threads.",
				Transform:   transform.FromField("Threads"),
			},
			{
				Name:        "nice",
				Type:        proto.ColumnType_INT,
				Description: "The process' nice value.",
				Transform:   transform.FromField("Nice"),
			},
			{
				Name:        "cgroup_path",
				Type:        proto.ColumnType_STRING,
				Description: "The CGroup path of the process.",
				Transform:   transform.FromField("CgroupPath"), //.Transform(TrimString),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: listOSQueryProcess,
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

//// LIST FUNCTIONS

func listOSQueryProcess(ctx context.Context, d *plugin.QueryData, h *plugin.HydrateData) (interface{}, error) {

	setLogLevel(ctx, d)

	hostname := d.EqualsQuals["hostname"].GetStringValue()
	plugin.Logger(ctx).Debug("retrieving list of processes", "hostname", hostname)

	connection, err := getSSHConnection(ctx, d, hostname, false)
	if err != nil {
		plugin.Logger(ctx).Error("error retrieving connection", "error", err)
		return nil, err
	}

	plugin.Logger(ctx).Debug("connection retrieved")

	session, err := connection.NewSession()
	if err != nil {
		plugin.Logger(ctx).Error("error creating session", "error", err)
		return nil, err
	}
	defer session.Close()

	plugin.Logger(ctx).Debug("session open")

	var output bytes.Buffer
	session.Stdout = &output
	command := `osqueryi --json "select * from processes;"`
	if err := session.Run(command); err != nil {
		plugin.Logger(ctx).Error("error running query", "command", command, "error", err)
		return nil, err
	}

	plugin.Logger(ctx).Debug("command run")

	processes := []osQueryProcess{}
	if err = json.Unmarshal(output.Bytes(), &processes); err != nil {
		plugin.Logger(ctx).Error("error unmarshalling query result", "error", err)
		return nil, err
	}

	for _, p := range processes {
		p.Hostname = hostname
		plugin.Logger(ctx).Debug("streaming process", "data", toPrettyJSON(&p))
		d.StreamListItem(ctx, p)
	}
	return nil, nil
}

type osQueryProcess struct {
	Hostname         string `json:"hostname"`
	PID              string `json:"pid"`
	Name             string `json:"name"`
	Path             string `json:"path"`
	Cmdline          string `json:"cmdline"`
	State            string `json:"state"`
	Cwd              string `json:"cwd"`
	Root             string `json:"root"`
	UID              string `json:"uid"`
	GID              string `json:"gid"`
	EUID             string `json:"euid"`
	EGID             string `json:"egid"`
	SUID             string `json:"suid"`
	SGID             string `json:"sgid"`
	OnDisk           string `json:"on_disk"`
	WiredSize        string `json:"wired_size"`
	ResidentSize     string `json:"resident_size"`
	TotalSize        string `json:"total_size"`
	UserTime         string `json:"user_time"`
	SystemTime       string `json:"system_time"`
	DiskBytesRead    string `json:"disk_bytes_read"`
	DiskBytesWritten string `json:"disk_bytes_written"`
	StartTime        string `json:"start_time"`
	Parent           string `json:"parent"`
	Pgroup           string `json:"pgroup"`
	Threads          string `json:"threads"`
	Nice             string `json:"nice"`
	CgroupPath       string `json:"cgroup_path"`
}
