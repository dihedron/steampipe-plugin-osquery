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
				Name:        "cgroup_path",
				Type:        proto.ColumnType_STRING,
				Description: "The CGroup path of the process.",
				Transform:   transform.FromField("CgroupPath"),
			},
			{
				Name:        "cmdline",
				Type:        proto.ColumnType_STRING,
				Description: "The command line of the process.",
				Transform:   transform.FromField("Cmdline"),
			},
			{
				Name:        "cwd",
				Type:        proto.ColumnType_STRING,
				Description: "The working directory of the process.",
				Transform:   transform.FromField("Cwd"),
			},

			// DiskBytesRead    string `json:"disk_bytes_read"`
			// DiskBytesWritten string `json:"disk_bytes_written"`
			// Egid             string `json:"egid"`
			// Euid             string `json:"euid"`
			// Gid              string `json:"gid"`
			// Name             string `json:"name"`
			// Nice             string `json:"nice"`
			// OnDisk           string `json:"on_disk"`
			// Parent           string `json:"parent"`
			// Path             string `json:"path"`
			// Pgroup           string `json:"pgroup"`
			// Pid              string `json:"pid"`
			// ResidentSize     string `json:"resident_size"`
			// Root             string `json:"root"`
			// Sgid             string `json:"sgid"`
			// StartTime        string `json:"start_time"`
			// State            string `json:"state"`
			// Suid             string `json:"suid"`
			// SystemTime       string `json:"system_time"`
			// Threads          string `json:"threads"`
			// TotalSize        string `json:"total_size"`
			// UID              string `json:"uid"`
			// UserTime         string `json:"user_time"`
			// WiredSize        string `json:"wired_size"`

			{
				Name:        "pid",
				Type:        proto.ColumnType_INT,
				Description: "The process PID.",
				Transform:   transform.FromField("Pid"),
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

	// result := users.Get(client, id)
	// var user *users.User
	// user, err = result.Extract()
	// if err != nil {
	// 	plugin.Logger(ctx).Error("error retrieving user", "error", err)
	// 	return nil, err
	// }
	return nil, nil
}

type osQueryProcess struct {
	Hostname         string `json:"hostname"`
	CgroupPath       string `json:"cgroup_path"`
	Cmdline          string `json:"cmdline"`
	Cwd              string `json:"cwd"`
	DiskBytesRead    string `json:"disk_bytes_read"`
	DiskBytesWritten string `json:"disk_bytes_written"`
	Egid             string `json:"egid"`
	Euid             string `json:"euid"`
	Gid              string `json:"gid"`
	Name             string `json:"name"`
	Nice             string `json:"nice"`
	OnDisk           string `json:"on_disk"`
	Parent           string `json:"parent"`
	Path             string `json:"path"`
	Pgroup           string `json:"pgroup"`
	Pid              string `json:"pid"`
	ResidentSize     string `json:"resident_size"`
	Root             string `json:"root"`
	Sgid             string `json:"sgid"`
	StartTime        string `json:"start_time"`
	State            string `json:"state"`
	Suid             string `json:"suid"`
	SystemTime       string `json:"system_time"`
	Threads          string `json:"threads"`
	TotalSize        string `json:"total_size"`
	UID              string `json:"uid"`
	UserTime         string `json:"user_time"`
	WiredSize        string `json:"wired_size"`
}
