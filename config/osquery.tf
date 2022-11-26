connection "osquery" {
    # the path to the plugin
    plugin    = "local/osquery"
    # authentication info
    username = "developer"
    password = "my-s3cr3t-p4ssw0rd!"
    # private_key = "/home/developer/.ssh/id_ed25519"
    trace_level = "TRACE"
}