package main

import (
	"github.com/dihedron/steampipe-plugin-osquery/osquery"
	"github.com/turbot/steampipe-plugin-sdk/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{PluginFunc: osquery.Plugin})
}
