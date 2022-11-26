package osquery

import (
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/schema"
)

type osqueryConfig struct {
	Username   *string `cty:"username"`
	Password   *string `cty:"password"`
	PrivateKey *string `cty:"private_key"`
	TraceLevel *string `cty:"trace_level"`
}

var ConfigSchema = map[string]*schema.Attribute{
	"username": {
		Type: schema.TypeString,
	},
	"password": {
		Type: schema.TypeString,
	},
	"private_key": {
		Type: schema.TypeString,
	},
	"trace_level": {
		Type: schema.TypeString,
	},
}

func ConfigInstance() interface{} {
	return &osqueryConfig{}
}

// GetConfig :: retrieve and cast connection config from query data
func GetConfig(connection *plugin.Connection) osqueryConfig {
	if connection == nil || connection.Config == nil {
		return osqueryConfig{}
	}
	config, _ := connection.Config.(osqueryConfig)

	return config
}
