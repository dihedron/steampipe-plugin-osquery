.PHONY: plugin
plugin:
	@go build

.PHONY: clean
clean:
	@rm -rf steampipe-plugin-osquery

.PHONY: install
install: plugin
	@mkdir -p ~/.steampipe/plugins/local/osquery
	@cp steampipe-plugin-osquery ~/.steampipe/plugins/local/osquery/osquery.plugin
	@cp config/osquery.tf ~/.steampipe/config/osquery.spc