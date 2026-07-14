package httpclient

import (
	"context"
	"fmt"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/warpstreamlabs/bento/public/service"
	"github.com/warpstreamlabs/bento/public/service/integration"
)

// TestIntegrationAWSSigV4STS validates AWS SigV4 signing end-to-end against a
// real AWS endpoint. It signs a GetCallerIdentity request to STS, which
// strictly validates the signature and requires no IAM permissions beyond
// having valid credentials, making it a zero-provisioning signing smoke test.
//
// Authenticate a terminal with AWS credentials (env vars or an SSO profile)
// and run it explicitly:
//
//	export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... AWS_REGION=us-east-1
//	go test ./internal/httpclient/ -run TestIntegrationAWSSigV4STS -v
//
// It is skipped during normal test runs (via integration.CheckSkip) and skips
// cleanly when no credentials are available.
func TestIntegrationAWSSigV4STS(t *testing.T) {
	integration.CheckSkip(t)

	ctx := context.Background()

	// Resolve the default credential chain, and skip (rather than fail) when no
	// credentials are present so the test is safe to run anywhere.
	awsConf, err := awsconfig.LoadDefaultConfig(ctx)
	require.NoError(t, err)
	if awsConf.Credentials == nil {
		t.Skip("no AWS credential provider resolved")
	}
	if _, err := awsConf.Credentials.Retrieve(ctx); err != nil {
		t.Skipf("no AWS credentials available: %v", err)
	}

	region := awsConf.Region
	if region == "" {
		region = "us-east-1"
	}

	// retries: 0 so a SignatureDoesNotMatch surfaces immediately rather than
	// being retried.
	conf := parseConfig(t, fmt.Sprintf(`
url: https://sts.%[1]s.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15
verb: GET
retries: 0
aws_sigv4:
  enabled: true
  region: %[1]s
  service: sts
`, region))

	client, err := NewClientFromOldConfig(conf, service.MockResources())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close(ctx) })

	resBatch, err := client.Send(ctx, service.MessageBatch{service.NewMessage(nil)})
	require.NoError(t, err, "STS rejected the signed request")
	require.Len(t, resBatch, 1)

	body, err := resBatch[0].AsBytes()
	require.NoError(t, err)
	// A valid signature yields the caller identity; an invalid one would have
	// been a non-2xx handled as an error above.
	assert.Contains(t, string(body), "GetCallerIdentityResult")
	t.Logf("STS accepted the SigV4-signed request:\n%s", string(body))
}
