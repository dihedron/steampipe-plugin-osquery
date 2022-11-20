package osquery

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/turbot/steampipe-plugin-sdk/plugin"
	"golang.org/x/crypto/ssh"
)

const SSHConnection = "SSHConnection::"

func getSSHConnection(ctx context.Context, d *plugin.QueryData, hostname string, nocache bool) (*ssh.Client, error) {
	plugin.Logger(ctx).Debug("acquiring SSH connection", "hostname", hostname)

	// load connection from cache, which preserves throttling protection etc
	if cachedData, ok := d.ConnectionManager.Cache.Get(SSHConnection + hostname); ok && !nocache {
		plugin.Logger(ctx).Debug("returning SSH connection from cache", "hostname", hostname)
		return cachedData.(*ssh.Client), nil
	}

	osqueryConfig := GetConfig(d.Connection)

	if osqueryConfig.Username == nil {
		plugin.Logger(ctx).Error("no valid username")
		return nil, errors.New("no valid username in configuration")
	}
	sshConfig := &ssh.ClientConfig{
		User:            *osqueryConfig.Username,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	if osqueryConfig.Password != nil {
		plugin.Logger(ctx).Debug("authenticating SSH connection with username/password", "username", *osqueryConfig.Username, "password", *osqueryConfig.Password)
		sshConfig.Auth = append(sshConfig.Auth, ssh.Password(*osqueryConfig.Password))
	} else if osqueryConfig.PrivateKey != nil {
		plugin.Logger(ctx).Debug("authenticating SSH connection with username/private key", "username", *osqueryConfig.Username, "private key", *osqueryConfig.PrivateKey)
		privateKey, err := os.ReadFile(*osqueryConfig.PrivateKey)
		if err != nil {
			plugin.Logger(ctx).Error("error reading private key", "path", *osqueryConfig.PrivateKey)
			return nil, fmt.Errorf("error reading private key %s: %w", *osqueryConfig.PrivateKey, err)
		}
		signer, err := ssh.ParsePrivateKey(privateKey)
		if err != nil {
			plugin.Logger(ctx).Error("error parsing private key", "path", *osqueryConfig.PrivateKey)
			return nil, fmt.Errorf("error parsing private key %s: %w", *osqueryConfig.PrivateKey, err)
		}
		sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(signer))
	}

	// TODO: fix port!!!
	client, err := ssh.Dial("tcp", hostname+":22", sshConfig)
	if err != nil {
		plugin.Logger(ctx).Error("error dialing target", "hostname", hostname)
		return nil, fmt.Errorf("error dialing target %s: %w", hostname, err)
	}

	// save to cache
	plugin.Logger(ctx).Debug("saving SSH connection to cache")
	d.ConnectionManager.Cache.Set(SSHConnection+hostname, client)

	return nil, nil
}
