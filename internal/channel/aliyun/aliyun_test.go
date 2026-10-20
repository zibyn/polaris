package aliyun

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zibyn/polaris/internal/channel"
)

// The worked example from Aliyun's RPC signature (v1) documentation.
func TestSignatureMatchesAliyunExample(t *testing.T) {
	params := url.Values{
		"AccessKeyId":      {"testid"},
		"Action":           {"DescribeRegions"},
		"Format":           {"XML"},
		"SignatureMethod":  {"HMAC-SHA1"},
		"SignatureNonce":   {"3ee8c1b8-83d3-44af-a94f-4e0ad82fd6cf"},
		"SignatureVersion": {"1.0"},
		"Timestamp":        {"2016-02-23T12:46:24Z"},
		"Version":          {"2014-05-26"},
	}
	if got := sign("GET", params, "testsecret"); got != "OLeaidS1JvxuMvnyHOwuJ+uX5qY=" {
		t.Errorf("signature %q", got)
	}
}

// stub stands in for dypnsapi.aliyuncs.com and answers with reply.
func stub(t *testing.T, reply map[string]any) chan url.Values {
	t.Helper()
	reqs := make(chan url.Values, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		reqs <- r.PostForm
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(ts.Close)
	old := endpoint
	endpoint = ts.URL
	t.Cleanup(func() { endpoint = old })
	return reqs
}

var settings = map[string]string{
	"accessKeyId": "AKID", "accessKeySecret": "AKSECRET", "signName": "速通互联验证码", "templateCode": "100001",
}

func TestSendsOwnCodeWithSendSmsVerifyCode(t *testing.T) {
	reqs := stub(t, map[string]any{"Code": "OK", "Message": "成功", "Success": true})
	ch, err := channel.Get("aliyun-pnvs-sms").New(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Send(context.Background(), "+8613800001111", "123456"); err != nil {
		t.Fatal(err)
	}
	p := <-reqs
	var tp map[string]string
	_ = json.Unmarshal([]byte(p.Get("TemplateParam")), &tp)
	if p.Get("Action") != "SendSmsVerifyCode" || p.Get("Version") != "2017-05-25" ||
		p.Get("PhoneNumber") != "13800001111" || p.Get("SignName") != "速通互联验证码" ||
		p.Get("TemplateCode") != "100001" || p.Get("AccessKeyId") != "AKID" ||
		tp["code"] != "123456" || tp["min"] != "5" {
		t.Errorf("request: %v", p)
	}
	sig := p.Get("Signature")
	p.Del("Signature")
	if sig == "" || sig != sign("POST", p, "AKSECRET") {
		t.Errorf("signature %q", sig)
	}
}

func TestAliyunErrorsSurface(t *testing.T) {
	stub(t, map[string]any{"Code": "isv.BUSINESS_LIMIT_CONTROL", "Message": "触发号码天级流控"})
	ch, _ := channel.Get("aliyun-pnvs-sms").New(settings)
	if err := ch.Send(context.Background(), "+8613800001111", "123456"); err == nil || !strings.Contains(err.Error(), "触发号码天级流控") {
		t.Errorf("err = %v", err)
	}
}

func TestOnlyMainlandNumbers(t *testing.T) {
	reqs := stub(t, map[string]any{"Code": "OK"})
	ch, _ := channel.Get("aliyun-pnvs-sms").New(settings)
	if err := ch.Send(context.Background(), "+14155550100", "123456"); err == nil {
		t.Error("sent to a +1 number")
	}
	if len(reqs) != 0 {
		t.Error("called Aliyun for a +1 number")
	}
}
