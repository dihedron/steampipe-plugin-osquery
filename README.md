# steampipe-plugin-osquery

A Steampipe plugin to run query on remote hosts via SSH and OSQuery.

One by one, this plugin will expose all standard OSQuery tables; in order to run it it is necessary to have a user that can SSH into the remote host, and the name of the host must be specified in the query.

**KNOWN LIMITATIONS**: it assumes that SSHd is listening on port :22, and it only works against boxes that have SSH running and osquery installed.

```bash
$> steampipe query "select * from osquery_process where hostname='myhost';"
```