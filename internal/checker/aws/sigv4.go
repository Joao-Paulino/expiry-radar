// Package aws checks Amazon Web Services for things that expire. Step 1:
// ACM and IAM server certificates. It signs requests itself (SigV4, Go
// standard library, no AWS SDK) and only calls list operations.
package aws

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// credentials are temporary AWS credentials (never static keys).
type credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

const amzDateFormat = "20060102T150405Z"

// awsEscape is RFC 3986 percent-encoding as SigV4 requires: unreserved
// characters as they are, everything else %XX (upper case).
func awsEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hashHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// canonicalRequest sets Host and X-Amz-Date and returns the canonical
// request and the signed header list. Every header already set on req
// is signed (callers set only what must be signed).
func canonicalRequest(req *http.Request, body []byte, at time.Time) (string, string) {
	req.Header.Set("X-Amz-Date", at.UTC().Format(amzDateFormat))
	host := req.URL.Host
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	q, _ := url.ParseQuery(req.URL.RawQuery)
	var pairs []string
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, awsEscape(k)+"="+awsEscape(v))
		}
	}
	sort.Strings(pairs)

	headers := map[string]string{"host": host}
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "user-agent" || lk == "content-length" {
			continue
		}
		headers[lk] = strings.Join(strings.Fields(strings.Join(vs, ",")), " ")
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, k := range names {
		ch.WriteString(k + ":" + headers[k] + "\n")
	}
	signed := strings.Join(names, ";")
	return strings.Join([]string{req.Method, path, strings.Join(pairs, "&"), ch.String(), signed, hashHex(body)}, "\n"), signed
}

// signV4 signs req with AWS Signature Version 4 (HMAC-SHA256).
func signV4(req *http.Request, body []byte, c credentials, region, service string, at time.Time) {
	if c.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	canon, signed := canonicalRequest(req, body, at)
	day := at.UTC().Format("20060102")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + at.UTC().Format(amzDateFormat) + "\n" + scope + "\n" + hashHex([]byte(canon))
	k := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), day)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKeyID+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}
