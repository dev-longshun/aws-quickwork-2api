package outbound

import "testing"

func TestParseListKiroFormats(t *testing.T) {
	cases := []struct {
		in, scheme, url, label string
	}{
		{"socks5://u:p@1.2.3.4:1080", "http", "socks5://u:p@1.2.3.4:1080", "socks5://1.2.3.4:1080"},
		{"u:p@1.2.3.4:8080", "http", "http://u:p@1.2.3.4:8080", "http://1.2.3.4:8080"},
		{"1.2.3.4:8080:user:pa:ss", "http", "http://user:pa%3Ass@1.2.3.4:8080", "http://1.2.3.4:8080"},
		{"1.2.3.4:1080:user:pass", "socks5", "socks5://user:pass@1.2.3.4:1080", "socks5://1.2.3.4:1080"},
		{"socks5h://Host.Example:1080", "http", "socks5://host.example:1080", "socks5://host.example:1080"},
		{"1.2.3.4:3128", "http", "http://1.2.3.4:3128", "http://1.2.3.4:3128"},
		{"socks5://1.2.3.4:1080:u:p", "http", "socks5://u:p@1.2.3.4:1080", "socks5://1.2.3.4:1080"},
	}
	for _, c := range cases {
		got, err := ParseListWithDefault(c.in, c.scheme)
		if err != nil || len(got) != 1 || got[0].URL != c.url || got[0].Label != c.label {
			t.Errorf("%q: got %+v err %v, want %s", c.in, got, err, c.url)
		}
	}
}

func TestParseListKiroJSON(t *testing.T) {
	got, err := ParseList(`[{"name":"US-1","url":"socks5://1.2.3.4:1080","username":"u","password":"p"},{"name":"HK","url":"http://5.6.7.8:80"}]`)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %+v err %v", got, err)
	}
	if got[0].URL != "socks5://u:p@1.2.3.4:1080" || got[0].Label != "US-1" || got[1].Label != "HK" {
		t.Errorf("got %+v", got)
	}
}

func TestParseListRejects(t *testing.T) {
	for _, in := range []string{"https://1.2.3.4:443", "ftp://x:21", "not a proxy", "[{bad json"} {
		if _, err := ParseList(in); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}
