package aws

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Expected values: the first two are the official AWS SigV4 test suite
// (get-vanilla, get-vanilla-query-order-key-case); all four were also
// computed with botocore's SigV4Auth for the same inputs.
func TestSignV4_Vectors(t *testing.T) {
	at := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	plain := credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	session := plain
	session.SessionToken = "SESSION/TOKEN+X="
	cases := []struct {
		name, method, url, region, service, body, want string
		headers                                        map[string]string
		creds                                          credentials
	}{
		{"vanilla", "GET", "https://example.amazonaws.com/", "us-east-1", "service", "",
			"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31", nil, plain},
		{"query order", "GET", "https://example.amazonaws.com/?Param2=value2&Param1=value1", "us-east-1", "service", "",
			"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500", nil, plain},
		{"json 1.1 with session token", "POST", "https://acm.eu-west-1.amazonaws.com/", "eu-west-1", "acm", `{"MaxItems":100}`,
			"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/eu-west-1/acm/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=6ff4b7cc37bb5afa9e22f52e1d4af51746d004995d4ea58237b35a8d09a4b124",
			map[string]string{"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": "CertificateManager.ListCertificates"}, session},
		{"query api with escaping", "GET", "https://iam.amazonaws.com/?Action=ListServerCertificates&Version=2010-05-08&Marker=a%2Fb%20c~d%2Ae", "us-east-1", "iam", "",
			"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=4a3956122580b2271b69ea17a177078e120c8d0bf4c63880627e65de485af2d6", nil, session},
		{"key prefix sort (key, then value)", "GET", "https://example.amazonaws.com/?a-b=2&a=1&Filter.1.Name=x&Filter.1=y", "us-east-1", "service", "",
			"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=4fe501b68c0a909b0a264d701fd3bfa679d2964c1e68f18a012696d6da3a41a8", nil, plain},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(c.method, c.url, strings.NewReader(c.body))
		for k, v := range c.headers {
			req.Header.Set(k, v)
		}
		signV4(req, []byte(c.body), c.creds, c.region, c.service, at)
		if got := req.Header.Get("Authorization"); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
		if c.creds.SessionToken != "" && req.Header.Get("X-Amz-Security-Token") != c.creds.SessionToken {
			t.Errorf("%s: session token header missing", c.name)
		}
	}
}
