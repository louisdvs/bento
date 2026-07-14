package httpclient

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/warpstreamlabs/bento/public/service"
)

func parseConfig(t *testing.T, yaml string) OldConfig {
	t.Helper()
	spec := service.NewConfigSpec().Field(ConfigField("POST", false))
	parsed, err := spec.ParseYAML(yaml, nil)
	require.NoError(t, err)
	conf, err := ConfigFromParsed(parsed)
	require.NoError(t, err)
	return conf
}

func TestAWSSigV4Disabled(t *testing.T) {
	// Absent block and explicitly-disabled block must both yield no signer.
	for _, yaml := range []string{
		`url: https://example.com/foo`,
		`
url: https://example.com/foo
aws_sigv4:
  enabled: false
  region: us-east-1
  service: bedrock-runtime
`,
	} {
		conf := parseConfig(t, yaml)
		assert.Nil(t, conf.awsSigV4)
	}
}

func TestAWSSigV4RequiresRegionAndService(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		errSubstr string
	}{
		{
			name: "missing service",
			yaml: `
url: https://example.com/foo
aws_sigv4:
  enabled: true
  region: us-east-1
`,
			errSubstr: "aws_sigv4.service",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := service.NewConfigSpec().Field(ConfigField("POST", false))
			parsed, err := spec.ParseYAML(test.yaml, nil)
			require.NoError(t, err)
			_, err = ConfigFromParsed(parsed)
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.errSubstr)
		})
	}
}

// newTestSigner builds a signer directly with static credentials, bypassing the
// AWS default chain so the test is hermetic (no environment/IMDS/STS access).
func newTestSigner(t *testing.T, region, svc, id, secret, token string) *awsSigV4Signer {
	t.Helper()
	c := awsSigV4Config{
		Region:     region,
		Service:    svc,
		CredID:     id,
		CredSecret: secret,
		CredToken:  token,
	}
	signer, err := c.signer(context.Background())
	require.NoError(t, err)
	require.NotNil(t, signer)
	return signer
}

func TestAWSSigV4SignsRequest(t *testing.T) {
	signer := newTestSigner(t, "us-east-1", "bedrock-runtime", "AKIDEXAMPLE", "secretkey", "")

	req, err := http.NewRequest("POST", "https://bedrock-runtime.us-east-1.amazonaws.com/model/foo/invoke", strings.NewReader(`{"inputText":"hello"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	require.NoError(t, signer.Sign(context.Background(), req))

	authz := req.Header.Get("Authorization")
	assert.True(t, strings.HasPrefix(authz, "AWS4-HMAC-SHA256 "), "unexpected auth header: %q", authz)
	assert.Contains(t, authz, "Credential=AKIDEXAMPLE/")
	assert.Contains(t, authz, "us-east-1/bedrock-runtime/aws4_request")
	assert.Contains(t, authz, "SignedHeaders=")
	assert.Contains(t, authz, "Signature=")

	assert.NotEmpty(t, req.Header.Get("X-Amz-Date"))
	// Host must be populated (the signer signs it) even though http.NewRequest
	// leaves req.Host empty.
	assert.Equal(t, "bedrock-runtime.us-east-1.amazonaws.com", req.Host)
	assert.Equal(t, "bedrock-runtime.us-east-1.amazonaws.com", req.Header.Get("Host"))
	// No session token was configured, so the header must be absent.
	assert.Empty(t, req.Header.Get("X-Amz-Security-Token"))
}

func TestAWSSigV4TemporaryCredentials(t *testing.T) {
	signer := newTestSigner(t, "eu-west-2", "execute-api", "AKIDEXAMPLE", "secretkey", "session-token-abc")

	req, err := http.NewRequest("GET", "https://api.eu-west-2.amazonaws.com/things", nil)
	require.NoError(t, err)

	require.NoError(t, signer.Sign(context.Background(), req))

	// Temporary credentials must propagate the security token header, and it
	// must be part of the signed headers.
	assert.Equal(t, "session-token-abc", req.Header.Get("X-Amz-Security-Token"))
	assert.Contains(t, req.Header.Get("Authorization"), "x-amz-security-token")
}

func TestAWSSigV4ReSignsWithDistinctSignaturePerBody(t *testing.T) {
	signer := newTestSigner(t, "us-east-1", "s3", "AKIDEXAMPLE", "secretkey", "")

	sign := func(body string) string {
		req, err := http.NewRequest("PUT", "https://bucket.s3.us-east-1.amazonaws.com/key", strings.NewReader(body))
		require.NoError(t, err)
		require.NoError(t, signer.Sign(context.Background(), req))
		return req.Header.Get("Authorization")
	}

	// Different bodies hash differently, so the payload is genuinely signed
	// (not UNSIGNED-PAYLOAD) and the signatures must differ.
	assert.NotEqual(t, sign("body-one"), sign("body-two"))
}

func TestAWSSigV4EmptyBodyHash(t *testing.T) {
	signer := newTestSigner(t, "us-east-1", "s3", "AKIDEXAMPLE", "secretkey", "")

	req, err := http.NewRequest("GET", "https://bucket.s3.us-east-1.amazonaws.com/key", nil)
	require.NoError(t, err)

	// A nil body must sign as the SHA-256 of the empty string rather than error.
	require.NoError(t, signer.Sign(context.Background(), req))
	assert.Contains(t, req.Header.Get("Authorization"), "Signature=")
}

func TestAWSSigV4EndToEndViaRequestCreator(t *testing.T) {
	conf := parseConfig(t, `
url: https://bedrock-runtime.us-east-1.amazonaws.com/model/foo/invoke
verb: POST
headers:
  Content-Type: application/json
aws_sigv4:
  enabled: true
  region: us-east-1
  service: bedrock-runtime
  credentials:
    id: AKIDEXAMPLE
    secret: secretkey
`)
	require.NotNil(t, conf.awsSigV4)

	reqCreator, err := RequestCreatorFromOldConfig(conf, service.MockResources())
	require.NoError(t, err)

	batch := service.MessageBatch{service.NewMessage([]byte(`{"inputText":"hello"}`))}
	req, err := reqCreator.Create(batch)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256 "))
	assert.Contains(t, req.Header.Get("Authorization"), "us-east-1/bedrock-runtime/aws4_request")
	assert.NotEmpty(t, req.Header.Get("X-Amz-Date"))
}
