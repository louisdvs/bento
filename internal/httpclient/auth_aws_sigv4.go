package httpclient

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"

	sigv4creds "github.com/aws/smithy-go/aws-http-auth/credentials"
	"github.com/aws/smithy-go/aws-http-auth/sigv4"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/warpstreamlabs/bento/public/service"
)

const (
	hcFieldAWSSigV4            = "aws_sigv4"
	hcFieldAWSSigV4Enabled     = "enabled"
	hcFieldAWSSigV4Region      = "region"
	hcFieldAWSSigV4Service     = "service"
	hcFieldAWSSigV4Credentials = "credentials"
	hcFieldAWSSigV4CredID      = "id"
	hcFieldAWSSigV4CredSecret  = "secret"
	hcFieldAWSSigV4CredToken   = "token"
)

func awsSigV4FieldSpec() *service.ConfigField {
	return service.NewObjectField(hcFieldAWSSigV4,
		service.NewBoolField(hcFieldAWSSigV4Enabled).
			Description("Whether to sign requests with AWS Signature Version 4.").
			Default(false),
		service.NewStringField(hcFieldAWSSigV4Region).
			Description("The AWS region to sign requests for. Required when `enabled` is set to `true`.").
			Default(""),
		service.NewStringField(hcFieldAWSSigV4Service).
			Description("The name of the AWS service to sign requests for, for example `bedrock-runtime` or `execute-api`. Required when `enabled` is set to `true`.").
			Default(""),
		service.NewObjectField(hcFieldAWSSigV4Credentials,
			service.NewStringField(hcFieldAWSSigV4CredID).
				Description("The ID of credentials to use.").
				Default("").Advanced(),
			service.NewStringField(hcFieldAWSSigV4CredSecret).
				Description("The secret for the credentials being used.").
				Default("").Advanced().Secret(),
			service.NewStringField(hcFieldAWSSigV4CredToken).
				Description("The token for the credentials being used, required when using short term credentials.").
				Default("").Advanced(),
		).
			Description("Optional manual configuration of AWS credentials to use. When omitted the [default credential chain](/docs/guides/cloud/aws) is used (environment variables, shared credentials/config files, IAM roles, etc.).").
			Advanced().
			Optional(),
	).
		Description(`Allows you to sign HTTP requests with [AWS Signature Version 4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html), which is required by many AWS HTTP APIs such as Amazon Bedrock.`).
		Advanced().
		Version("1.20.0").
		Optional()
}

// awsSigV4Config holds the parsed configuration for AWS SigV4 request signing.
type awsSigV4Config struct {
	Region     string
	Service    string
	CredID     string
	CredSecret string
	CredToken  string
}

func awsSigV4FromParsed(pConf *service.ParsedConfig) (*awsSigV4Signer, error) {
	if !pConf.Contains(hcFieldAWSSigV4) {
		return nil, nil
	}

	conf := pConf.Namespace(hcFieldAWSSigV4)

	enabled, err := conf.FieldBool(hcFieldAWSSigV4Enabled)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	var c awsSigV4Config
	if c.Region, err = conf.FieldString(hcFieldAWSSigV4Region); err != nil {
		return nil, err
	}
	if c.Service, err = conf.FieldString(hcFieldAWSSigV4Service); err != nil {
		return nil, err
	}
	if c.Service == "" {
		return nil, fmt.Errorf("field '%v.%v' is required when SigV4 signing is enabled", hcFieldAWSSigV4, hcFieldAWSSigV4Service)
	}

	creds := conf.Namespace(hcFieldAWSSigV4Credentials)
	if c.CredID, err = creds.FieldString(hcFieldAWSSigV4CredID); err != nil {
		return nil, err
	}
	if c.CredSecret, err = creds.FieldString(hcFieldAWSSigV4CredSecret); err != nil {
		return nil, err
	}
	if c.CredToken, err = creds.FieldString(hcFieldAWSSigV4CredToken); err != nil {
		return nil, err
	}

	return c.signer(context.Background())
}

// signer resolves an AWS credentials provider from the default chain (or the
// explicitly configured static credentials) and builds an awsSigV4Signer.
func (c awsSigV4Config) signer(ctx context.Context) (*awsSigV4Signer, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if c.Region != "" {
		opts = append(opts, awsconfig.WithRegion(c.Region))
	}
	if c.CredID != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			awscreds.NewStaticCredentialsProvider(c.CredID, c.CredSecret, c.CredToken),
		))
	}

	awsConf, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for SigV4 signing: %w", err)
	}

	region := c.Region
	if region == "" {
		region = awsConf.Region
	}
	if region == "" {
		return nil, fmt.Errorf("field '%v.%v' is required when SigV4 signing is enabled (and no region was resolved from the environment)", hcFieldAWSSigV4, hcFieldAWSSigV4Region)
	}
	if awsConf.Credentials == nil {
		return nil, fmt.Errorf("no AWS credentials were resolved for SigV4 signing")
	}

	return &awsSigV4Signer{
		signer:  sigv4.New(),
		creds:   awsConf.Credentials,
		region:  region,
		service: c.Service,
	}, nil
}

// awsSigV4Signer signs HTTP requests in place using AWS Signature Version 4.
type awsSigV4Signer struct {
	signer  *sigv4.Signer
	creds   aws.CredentialsProvider
	region  string
	service string
}

// Sign mutates req in place, adding the headers that constitute an AWS SigV4
// signature (Host, X-Amz-Date, Authorization, and X-Amz-Security-Token when the
// resolved credentials are temporary).
func (s *awsSigV4Signer) Sign(ctx context.Context, req *http.Request) error {
	creds, err := s.creds.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve AWS credentials for SigV4 signing: %w", err)
	}

	// The signer builds the "Host" header from req.Host, which http.NewRequest
	// leaves empty (the standard client would otherwise populate it from the
	// URL at send time). Populate it here so the signed value matches what's
	// transmitted.
	if req.Host == "" {
		req.Host = req.URL.Host
	}

	payloadHash, err := requestPayloadHash(req)
	if err != nil {
		return fmt.Errorf("failed to hash request payload for SigV4 signing: %w", err)
	}

	return s.signer.SignRequest(&sigv4.SignRequestInput{
		Request:     req,
		PayloadHash: payloadHash,
		Credentials: sigv4creds.Credentials{
			AccessKeyID:     creds.AccessKeyID,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:    creds.SessionToken,
		},
		Service: s.service,
		Region:  s.region,
	})
}

// requestPayloadHash returns the SHA-256 of the request body without consuming
// it. AWS requires the payload to be signed; relying on the signer's implicit
// hashing would fall back to UNSIGNED-PAYLOAD for the buffer-backed bodies this
// client produces, which many services reject.
func requestPayloadHash(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		h := sha256.Sum256(nil)
		return h[:], nil
	}
	if req.GetBody == nil {
		// We can't read the body without consuming it; let the signer decide
		// how to handle the payload hash.
		return nil, nil
	}

	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	defer body.Close()

	h := sha256.New()
	if _, err := io.Copy(h, body); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
