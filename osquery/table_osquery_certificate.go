package osquery

import (
	"context"

	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"
)

//// TABLE DEFINITION

func tableOSQueryCertificate(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "osquery_certificate",
		Description: "The system's certificates.",
		Columns: []*plugin.Column{
			{
				Name:        "hostname",
				Type:        proto.ColumnType_STRING,
				Description: "The name of the host whose certificates are being queried.",
				Transform:   transform.FromField("Hostname"),
			},

			{
				Name:        "common_name",
				Type:        proto.ColumnType_STRING,
				Description: "The certificate's common name.",
				Transform:   transform.FromField("CommonName"),
			},
			{
				Name:        "subject",
				Type:        proto.ColumnType_STRING,
				Description: "The certificate's subject.",
				Transform:   transform.FromField("Subject"),
			},
			{
				Name:        "issuer",
				Type:        proto.ColumnType_STRING,
				Description: "The certificate's issuer.",
				Transform:   transform.FromField("Issuer"),
			},
			{
				Name:        "ca",
				Type:        proto.ColumnType_INT,
				Description: "The certificate's CA.",
				Transform:   transform.FromField("CA"),
			},
			{
				Name:        "self_signed",
				Type:        proto.ColumnType_INT,
				Description: "Whether the certificate is self-signed.",
				Transform:   transform.FromField("SelfSigned").Transform(SafeInt(0)),
			},
			{
				Name:        "not_valid_before",
				Type:        proto.ColumnType_STRING,
				Description: "The certificate's beginning of validity date.",
				Transform:   transform.FromField("NotValidBefore"),
			},
			{
				Name:        "not_valid_after",
				Type:        proto.ColumnType_STRING,
				Description: "The certificate's end of validity date.",
				Transform:   transform.FromField("NotValidAfter"),
			},
			{
				Name:        "signing_algorithm",
				Type:        proto.ColumnType_STRING,
				Description: "The certificate's signing algorithm.",
				Transform:   transform.FromField("SigningAlgorithm"),
			},
			{
				Name:        "key_algorithm",
				Type:        proto.ColumnType_STRING,
				Description: "The certificate's key algorithm.",
				Transform:   transform.FromField("KeyAlgorithm"),
			},
			{
				Name:        "key_strength",
				Type:        proto.ColumnType_STRING,
				Description: "The certificate's key strength.",
				Transform:   transform.FromField("KeyStrength"),
			},
			{
				Name:        "key_usage",
				Type:        proto.ColumnType_STRING,
				Description: "The certificate's key usage.",
				Transform:   transform.FromField("KeyUsage"),
			},
			{
				Name:        "subject_key_id",
				Type:        proto.ColumnType_STRING,
				Description: "The certificate's subject key id.",
				Transform:   transform.FromField("SubjectKeyID"),
			},
			{
				Name:        "authority_key_id",
				Type:        proto.ColumnType_STRING,
				Description: "The certificate's authority key id.",
				Transform:   transform.FromField("AuthorityKeyID"),
			},
			{
				Name:        "sha1",
				Type:        proto.ColumnType_STRING,
				Description: "The certificate's SHA-1 sum.",
				Transform:   transform.FromField("SHA1"),
			},
			{
				Name:        "path",
				Type:        proto.ColumnType_STRING,
				Description: "The certificate's path.",
				Transform:   transform.FromField("Path"),
			},
			{
				Name:        "serial",
				Type:        proto.ColumnType_STRING,
				Description: "The certificate's serial.",
				Transform:   transform.FromField("Serial"),
			},
		},
		List: &plugin.ListConfig{
			Hydrate: makeListOSQuery[*osQueryCertificate]("select * from certificates;"),
			KeyColumns: plugin.KeyColumnSlice{
				&plugin.KeyColumn{
					Name:    "hostname",
					Require: plugin.Required,
				},
			},
		},
	}
}

type osQueryCertificate struct {
	Result
	CommonName       string `json:"common_name"`
	Subject          string `json:"subject"`
	Issuer           string `json:"issuer"`
	CA               string `json:"ca"`
	SelfSigned       string `json:"self_signed"`
	NotValidBefore   string `json:"not_valid_before"`
	NotValidAfter    string `json:"not_valid_after"`
	SigningAlgorithm string `json:"signing_algorithm"`
	KeyAlgorithm     string `json:"key_algorithm"`
	KeyStrength      string `json:"key_strength"`
	KeyUsage         string `json:"key_usage"`
	SubjectKeyID     string `json:"subject_key_id"`
	AuthorityKeyID   string `json:"authority_key_id"`
	SHA1             string `json:"sha1"`
	Path             string `json:"path"`
	Serial           string `json:"serial"`
}
