package probe

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type TLSInfo struct {
	Grade      string
	Version    string
	Expiry     string
	DaysLeft   int
	Expired    bool
	SelfSigned bool
}

type Result struct {
	URL           string
	FinalURL      string
	StatusCode    int
	Title         string
	ContentLength int64
	ContentType   string
	Server        string
	Tech          []string
	WAF           string
	TLS           *TLSInfo
	FaviconHash   string
	FaviconApp    string
	Words         int
	Lines         int
	Error         string
}

type Options struct {
	Timeout        time.Duration
	ProxyURL       string
	UserAgent      string
	Headers        map[string]string
	FollowRedirect bool
	MaxRedirects   int
	TechDetect     bool
	WAFDetect      bool
	TLSScan        bool
	FaviconScan    bool
}

func newClient(opts Options) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	if opts.ProxyURL != "" {
		if pu, err := url.Parse(opts.ProxyURL); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	maxR := opts.MaxRedirects
	if maxR == 0 { maxR = 10 }
	return &http.Client{
		Timeout:   opts.Timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !opts.FollowRedirect { return http.ErrUseLastResponse }
			if len(via) >= maxR    { return http.ErrUseLastResponse }
			return nil
		},
	}
}

var titleRe = regexp.MustCompile(`(?i)<title[^>]*>([^<]{1,200})</title>`)

func Do(rawURL string, opts Options) *Result {
	r := &Result{URL: rawURL}
	if !strings.HasPrefix(rawURL, "http") {
		rawURL = "https://" + rawURL
		r.URL  = rawURL
	}
	client := newClient(opts)
	ua := opts.UserAgent
	if ua == "" { ua = "Mozilla/5.0 HX/1.0" }

	do := func(u string) (*http.Response, []byte, error) {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil { return nil, nil, err }
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "text/html,*/*;q=0.8")
		for k, v := range opts.Headers { req.Header.Set(k, v) }
		resp, err := client.Do(req)
		if err != nil { return nil, nil, err }
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		resp.Body.Close()
		return resp, body, nil
	}

	resp, body, err := do(rawURL)
	if err != nil {
		if strings.HasPrefix(rawURL, "https://") {
			resp2, body2, err2 := do(strings.Replace(rawURL, "https://", "http://", 1))
			if err2 != nil { r.Error = err.Error(); return r }
			resp, body = resp2, body2
		} else { r.Error = err.Error(); return r }
	}

	bodyStr := string(body)
	r.StatusCode    = resp.StatusCode
	r.FinalURL      = resp.Request.URL.String()
	r.ContentLength = resp.ContentLength
	if r.ContentLength < 0 { r.ContentLength = int64(len(body)) }
	r.ContentType   = resp.Header.Get("Content-Type")
	r.Server        = resp.Header.Get("Server")
	r.Words         = len(strings.Fields(bodyStr))
	r.Lines         = strings.Count(bodyStr, "\n")

	if m := titleRe.FindStringSubmatch(bodyStr); len(m) > 1 {
		t := strings.TrimSpace(strings.ReplaceAll(m[1], "\n", " "))
		if len(t) > 80 { t = t[:77] + "..." }
		r.Title = t
	}

	var cookies []string
	for _, c := range resp.Cookies()            { cookies = append(cookies, c.Name) }
	for _, v := range resp.Header["Set-Cookie"] { cookies = append(cookies, v) }

	if opts.TechDetect { r.Tech = detectTech(resp.Header, bodyStr, cookies) }
	if opts.WAFDetect  { r.WAF  = detectWAF(resp.Header, bodyStr, cookies) }

	if opts.TLSScan && strings.HasPrefix(r.FinalURL, "https") {
		host := resp.Request.URL.Hostname()
		port := resp.Request.URL.Port()
		if port == "" { port = "443" }
		r.TLS = getTLS(host + ":" + port)
	}
	if opts.FaviconScan {
		r.FaviconHash, r.FaviconApp = getFavicon(rawURL, client, ua)
	}
	return r
}

// ─── Tech detection ───────────────────────────────────────────────────────────

type tSig struct {
	name string
	h    map[string]string
	b    []string
	c    []string
}

var techSigs = []tSig{
	{"WordPress",     nil, []string{"wp-content/","wp-includes/"}, []string{"wordpress_","wp-settings"}},
	{"Joomla",        nil, []string{"/components/com_","Joomla!"}, []string{"joomla_"}},
	{"Drupal",        map[string]string{"x-generator":"Drupal"}, []string{"drupal.js"}, nil},
	{"Magento",       nil, []string{"mage/cookies","cdn.magento"}, []string{"frontend"}},
	{"Shopify",       map[string]string{"x-shopify-stage":""}, []string{"cdn.shopify.com"}, nil},
	{"Laravel",       nil, nil, []string{"laravel_session","XSRF-TOKEN"}},
	{"Django",        nil, []string{"csrfmiddlewaretoken"}, []string{"csrftoken"}},
	{"ASP.NET",       map[string]string{"x-aspnet-version":"","x-powered-by":"ASP.NET"}, nil, []string{"ASP.NET_SessionId"}},
	{"Spring Boot",   map[string]string{"x-application-context":""}, []string{"Whitelabel Error"}, nil},
	{"Express.js",    map[string]string{"x-powered-by":"Express"}, nil, nil},
	{"Flask",         nil, []string{"Werkzeug"}, nil},
	{"Rails",         nil, []string{"rails-ujs"}, nil},
	{"React",         nil, []string{"react-dom","data-reactroot","__NEXT_DATA__"}, nil},
	{"Vue.js",        nil, []string{"__vue__","vue.min.js"}, nil},
	{"Angular",       nil, []string{"ng-version","ng-app"}, nil},
	{"Next.js",       nil, []string{"__NEXT_DATA__","_next/static"}, nil},
	{"PHP",           map[string]string{"x-powered-by":"PHP"}, nil, []string{"PHPSESSID"}},
	{"Java",          nil, nil, []string{"JSESSIONID"}},
	{"Google Analytics", nil, []string{"google-analytics.com/analytics","gtag/js"}, nil},
	{"GraphQL",       nil, []string{"__typename","graphql"}, nil},
	{"Swagger",       nil, []string{"swagger-ui","swagger.json"}, nil},
	{"jQuery",        nil, []string{"jquery.min.js","jQuery v"}, nil},
	{"Bootstrap",     nil, []string{"bootstrap.min.css"}, nil},
	{"Tailwind",      nil, []string{"tailwindcss"}, nil},
	{"reCAPTCHA",     nil, []string{"google.com/recaptcha"}, nil},
}

func detectTech(hdrs map[string][]string, body string, cookies []string) []string {
	bodyL := strings.ToLower(body)
	seen  := map[string]bool{}
	var out []string
	for _, s := range techSigs {
		if seen[s.name] { continue }
		hit := false
		for hk, hv := range s.h {
			for k, vals := range hdrs {
				if strings.EqualFold(k, hk) {
					v := strings.ToLower(strings.Join(vals, " "))
					if hv == "" || strings.Contains(v, strings.ToLower(hv)) { hit = true; break }
				}
			}
			if hit { break }
		}
		if !hit { for _, kw := range s.b { if strings.Contains(bodyL, strings.ToLower(kw)) { hit = true; break } } }
		if !hit { for _, ck := range s.c { for _, c := range cookies { if strings.Contains(strings.ToLower(c), strings.ToLower(ck)) { hit = true; break } }; if hit { break } } }
		if hit { seen[s.name] = true; out = append(out, s.name) }
	}
	return out
}

// ─── WAF detection ────────────────────────────────────────────────────────────

type wSig struct {
	name string
	h    map[string]string
	c    []string
	b    []string
}

var wafSigs = []wSig{
	{"Cloudflare",   map[string]string{"cf-ray":"","server":"cloudflare"}, []string{"__cf_bm","cf_clearance"}, []string{"cloudflare"}},
	{"AWS WAF",      map[string]string{"x-amzn-requestid":""}, []string{"aws-waf-token"}, []string{"AWS WAF"}},
	{"Akamai",       nil, []string{"ak_bmsc","bm_sz"}, []string{"AkamaiGHost"}},
	{"Sucuri",       map[string]string{"x-sucuri-id":"","server":"sucuri"}, nil, []string{"Sucuri WebSite Firewall"}},
	{"Imperva",      map[string]string{"x-iinfo":""}, []string{"incap_ses","visid_incap"}, []string{"incapsula"}},
	{"ModSecurity",  map[string]string{"server":"mod_security"}, nil, []string{"ModSecurity"}},
	{"F5 BIG-IP",    map[string]string{"server":"bigip"}, []string{"BIGipServer"}, nil},
	{"Fortinet",     nil, []string{"FORTIWAFSID"}, []string{"FortiWeb"}},
	{"Barracuda",    map[string]string{"server":"barracuda"}, []string{"barra_counter_session"}, nil},
	{"DDoS-Guard",   map[string]string{"server":"ddos-guard"}, []string{"__ddg1"}, nil},
	{"Wordfence",    nil, nil, []string{"Generated by Wordfence"}},
	{"Reblaze",      map[string]string{"x-reblaze-protection":""}, []string{"rbzid"}, nil},
	{"Wallarm",      map[string]string{"x-wallarm-node":""}, nil, nil},
	{"Fastly WAF",   map[string]string{"x-fastly-request-id":""}, nil, []string{"Fastly error"}},
}

func detectWAF(hdrs map[string][]string, body string, cookies []string) string {
	bodyL := strings.ToLower(body)
	for _, s := range wafSigs {
		for hk, hv := range s.h {
			for k, vals := range hdrs {
				if strings.EqualFold(k, hk) {
					v := strings.ToLower(strings.Join(vals, " "))
					if hv == "" || strings.Contains(v, strings.ToLower(hv)) { return s.name }
				}
			}
		}
		for _, ck := range s.c { for _, c := range cookies { if strings.Contains(strings.ToLower(c), strings.ToLower(ck)) { return s.name } } }
		for _, kw := range s.b { if strings.Contains(bodyL, strings.ToLower(kw)) { return s.name } }
	}
	return ""
}

// ─── TLS ─────────────────────────────────────────────────────────────────────

var tlsVer = map[uint16]string{0x0301:"TLS 1.0",0x0302:"TLS 1.1",0x0303:"TLS 1.2",0x0304:"TLS 1.3"}
var tlsCiph = map[uint16]string{
	0x1301:"AES-128-GCM",0x1302:"AES-256-GCM",0x1303:"CHACHA20-POLY1305",
	0xC02F:"ECDHE-RSA-AES128-GCM",0xC030:"ECDHE-RSA-AES256-GCM",
	0xCCA8:"ECDHE-RSA-CHACHA20",0x002F:"RSA-AES128-CBC(weak)",
	0x0035:"RSA-AES256-CBC(weak)",0x000A:"3DES(very weak)",
}

func getTLS(hostport string) *TLSInfo {
	info := &TLSInfo{}
	hostname, _, _ := net.SplitHostPort(hostport)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second}, "tcp", hostport, &tls.Config{ServerName: hostname, InsecureSkipVerify: true})
	if err != nil { return info }
	defer conn.Close()
	st    := conn.ConnectionState()
	certs := st.PeerCertificates
	if len(certs) == 0 { return info }
	cert := certs[0]
	info.Expiry     = cert.NotAfter.Format("2006-01-02")
	info.DaysLeft   = int(time.Until(cert.NotAfter).Hours() / 24)
	info.Expired    = time.Now().After(cert.NotAfter)
	info.SelfSigned = cert.Issuer.CommonName == cert.Subject.CommonName
	ver := tlsVer[st.Version]; if ver == "" { ver = fmt.Sprintf("0x%04x", st.Version) }
	info.Version = ver
	ciph := tlsCiph[st.CipherSuite]; if ciph == "" { ciph = fmt.Sprintf("0x%04x", st.CipherSuite) }
	switch {
	case info.Expired || info.SelfSigned:                    info.Grade = "F"
	case strings.Contains(ver,"1.0")||strings.Contains(ver,"1.1"): info.Grade = "C"
	case strings.Contains(ciph,"weak")||strings.Contains(ciph,"3DES"): info.Grade = "B"
	case ver == "TLS 1.3":                                   info.Grade = "A+"
	default:                                                  info.Grade = "A"
	}
	return info
}

// ─── Favicon ─────────────────────────────────────────────────────────────────

var knownFav = map[int32]string{
	-559558149:"Kibana",-1609532888:"Jenkins",1763891671:"Grafana",
	-84053552:"GitLab",116323821:"Jira",1398293303:"Confluence",
	-674048716:"pgAdmin",2069091502:"phpMyAdmin",-1581128453:"WordPress",
	84023065:"Fortinet SSL VPN",-2012998724:"Exchange OWA",
	-2077474580:"SharePoint",1092226267:"Shopify",
}

func getFavicon(rawURL string, client *http.Client, ua string) (string, string) {
	base := strings.TrimRight(rawURL, "/")
	req, _ := http.NewRequest("GET", base+"/favicon.ico", nil)
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 { return "", "" }
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if len(data) == 0 { return "", "" }
	b64 := base64.StdEncoding.EncodeToString(data)
	h   := fnv.New32a()
	h.Write([]byte(b64))
	hash := int32(h.Sum32())
	return fmt.Sprintf("%d", hash), knownFav[hash]
}
