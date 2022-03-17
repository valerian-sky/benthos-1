package auth

import "github.com/benthosdev/benthos/v4/internal/docs"

// FieldSpec returns documentation authentication specs for Pulsar components
func FieldSpec() docs.FieldSpec {
	return docs.FieldAdvanced("auth", "Optional configuration of Pulsar authentication methods.").WithChildren(
		docs.FieldAdvanced("oauth2", "Parameters for Pulsar OAuth2 authentication.").WithChildren(
			docs.FieldBool("enabled", "Whether OAuth2 is enabled.", true),
			docs.FieldString("audience", "OAuth2 audience."),
			docs.FieldString("issuer_url", "OAuth2 issuer URL."),
			docs.FieldString("private_key_file", "File containing the private key."),
		),
		docs.FieldAdvanced("token", "Parameters for Pulsar Token authentication.").WithChildren(
			docs.FieldBool("enabled", "Whether Token Auth is enabled.", true),
			docs.FieldString("token", "Actual base64 encoded token."),
		),
		docs.FieldAdvanced("tls", "Custom TLS settings can be used to override system defaults.").WithChildren(
			docs.FieldBool("enabled", "Whether custom TLS settings are enabled.", true),
			docs.FieldString("root_cas_file", "This is a file, often with a .pem extension, containing a certificate chain from the parent trusted root certificate, to possible intermediate signing certificates, to the host certificate."),
			docs.FieldString("allow_insecure_connection", "Configure whether the Pulsar client accept untrusted TLS certificate from broker"),
			docs.FieldString("key_file", "The path of a certificate key to use."),
			docs.FieldString("cert_file", "The path to a certificate to use."),
		),
	).AtVersion("3.60.0")
}
