package profile

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func ptr(s string) *string { return &s }

func TestPatchParams(t *testing.T) {
	arg, err := Patch{
		Name: ptr(" 王小明 "), GivenName: ptr(""), Website: ptr("https://example.com/me"),
		Birthdate: ptr("0000-02-29"), Zoneinfo: ptr("Asia/Shanghai"), Locale: ptr("zh-hans-cn"),
		Address: &Address{StreetAddress: "1 号\r\n2 室", Country: " CN "},
	}.params()
	if err != nil {
		t.Fatal(err)
	}
	var set map[string]any
	_ = json.Unmarshal(arg.Set, &set)
	addr, _ := set["address"].(map[string]any)
	if arg.SetNickname || set["name"] != "王小明" || set["website"] != "https://example.com/me" || set["birthdate"] != "0000-02-29" ||
		set["zoneinfo"] != "Asia/Shanghai" || set["locale"] != "zh-Hans-CN" ||
		addr["street_address"] != "1 号\n2 室" || addr["country"] != "CN" || len(addr) != 2 ||
		!slices.Equal(arg.Clear, []string{"given_name"}) {
		t.Errorf("%s %v", arg.Set, arg.Clear)
	}

	if arg, _ := (Patch{Nickname: ptr(""), Address: &Address{Locality: " "}}).params(); !arg.SetNickname || !slices.Equal(arg.Clear, []string{"address"}) {
		t.Errorf("clear: %+v", arg)
	}

	for name, p := range map[string]Patch{
		"long name":          {Name: ptr(strings.Repeat("名", 65))},
		"control":            {FamilyName: ptr("a\nb")},
		"javascript":         {Profile: ptr("javascript:alert(1)")},
		"relative":           {Website: ptr("/me")},
		"space in url":       {Website: ptr("https://a.com/ b")},
		"bad date":           {Birthdate: ptr("2000-02-30")},
		"year 0000":          {Birthdate: ptr("0000")},
		"month only":         {Birthdate: ptr("2000-02")},
		"zone":               {Zoneinfo: ptr("Mars/Olympus")},
		"local zone":         {Zoneinfo: ptr("Local")},
		"locale":             {Locale: ptr("not a tag!")},
		"long postal":        {Address: &Address{PostalCode: "12345678901234567"}},
		"control in country": {Address: &Address{Country: "C\nN"}},
	} {
		if _, err := p.params(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
