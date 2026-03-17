package main

import (
	"bufio"
	"flag"
	"fmt"
	"hx/internal/probe"
	"hx/internal/reporter"
	"os"
	"strings"
	"sync"
	"time"
)

func printBanner() {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  \033[95m\033[1m██╗  ██╗██╗  ██╗\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[95m\033[1m██║  ██║╚██╗██╔╝\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[95m\033[1m███████║ ╚███╔╝ \033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[95m\033[1m██╔══██║ ██╔██╗ \033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[95m\033[1m██║  ██║██╔╝ ██╗\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[95m\033[1m╚═╝  ╚═╝╚═╝  ╚═╝\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mHX v1.0 — Advanced HTTP Probe\033[0m\n")
	fmt.Fprintf(os.Stderr, "  \033[93mby 0xWHITEROOM 「0xホワイトルーム」\033[0m\n\n")
}

func printHelp() {
	printBanner()
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mUSAGE\033[0m\n")
	fmt.Fprintf(os.Stderr, "    hx -u <url>  OR  cat urls.txt | hx\n\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mINPUT\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-u <url>\033[0m         Single URL\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-l <file>\033[0m        File of URLs\n")
	fmt.Fprintf(os.Stderr, "    \033[93mstdin\033[0m            cat urls.txt | hx\n\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mPROBES\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-td\033[0m              Tech stack detection\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-waf\033[0m             WAF/Firewall detection\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-tls\033[0m             TLS info + grade (A+/A/B/C/F)\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-fav\033[0m             Favicon hash (Shodan compatible)\n\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mFILTER\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-mc <200,403>\033[0m    Match status codes\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-fc <404,500>\033[0m    Filter status codes\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-ms <bytes>\033[0m      Match content length\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-fs <bytes>\033[0m      Filter content length\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-mt <string>\033[0m     Match title contains\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-ft <string>\033[0m     Filter title contains\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-er\033[0m              Exclude errors\n\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mCONFIG\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-c <int>\033[0m         Threads (default 50)\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-timeout <s>\033[0m     Timeout seconds (default 10)\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-p <url>\033[0m         Proxy http:// or socks5://\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-H <k:v>\033[0m         Custom header (repeatable)\n\n")
	fmt.Fprintf(os.Stderr, "  \033[96m\033[1mOUTPUT\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-o <file>\033[0m        Save TXT\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-oj <file>\033[0m       Save JSON\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-ojl <file>\033[0m      Save JSONL\n")
	fmt.Fprintf(os.Stderr, "    \033[93m-silent\033[0m          URLs only to stdout\n\n")
	fmt.Fprintf(os.Stderr, "  \033[92m\033[1mEXAMPLES\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mhx -u https://example.com\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mhx -u https://example.com -td -waf -tls -fav\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mcat subs.txt | hx -c 100 -mc 200,403 -er\033[0m\n")
	fmt.Fprintf(os.Stderr, "    \033[92mhx -l hosts.txt -waf -oj wafs.json\033[0m\n\n")
}

type multiFlag []string
func (f *multiFlag) String() string     { return strings.Join(*f, ",") }
func (f *multiFlag) Set(v string) error { *f = append(*f, v); return nil }

func main() {
	var headers multiFlag

	u       := flag.String("u",       "",    "")
	ul      := flag.String("l",       "",    "")
	td      := flag.Bool("td",        false, "")
	waf     := flag.Bool("waf",       false, "")
	tls     := flag.Bool("tls",       false, "")
	fav     := flag.Bool("fav",       false, "")
	c       := flag.Int("c",          50,    "")
	timeout := flag.Float64("timeout",10,    "")
	proxy   := flag.String("p",       "",    "")
	flag.Var(&headers, "H",                  "")
	mc      := flag.String("mc",      "",    "")
	fc      := flag.String("fc",      "",    "")
	ms      := flag.Int("ms",         -1,    "")
	fs      := flag.Int("fs",         -1,    "")
	mt      := flag.String("mt",      "",    "")
	ft      := flag.String("ft",      "",    "")
	er      := flag.Bool("er",        false, "")
	outTXT  := flag.String("o",       "",    "")
	outJSON := flag.String("oj",      "",    "")
	outJSONL:= flag.String("ojl",     "",    "")
	silent  := flag.Bool("silent",    false, "")
	version := flag.Bool("version",   false, "")

	flag.Usage = printHelp
	flag.Parse()

	if *version { fmt.Fprintln(os.Stderr, "hx v1.0  by FIN 「サイバー守護者」"); os.Exit(0) }
	if !*silent { printBanner() }

	// Collect URLs
	var urls []string
	if *u != "" { urls = append(urls, *u) }
	if *ul != "" {
		f, err := os.Open(*ul)
		if err != nil { fmt.Fprintf(os.Stderr, "\033[91m[-]\033[0m cannot open: %s\n", err); os.Exit(1) }
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
				urls = append(urls, line)
			}
		}
		f.Close()
	}
	stat, _ := os.Stdin.Stat()
	if stat.Mode()&os.ModeCharDevice == 0 {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" { urls = append(urls, line) }
		}
	}
	if len(urls) == 0 { printHelp(); os.Exit(0) }

	opts := probe.Options{
		Timeout:        time.Duration(*timeout * float64(time.Second)),
		ProxyURL:       *proxy,
		UserAgent:      "",
		Headers:        map[string]string{},
		FollowRedirect: true,
		MaxRedirects:   10,
		TechDetect:     *td,
		WAFDetect:      *waf,
		TLSScan:        *tls,
		FaviconScan:    *fav,
	}
	for _, h := range headers {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			opts.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	matchSC  := parseCodes(*mc)
	filterSC := parseCodes(*fc)

	rep, err := reporter.New(*outJSON, *outTXT, *outJSONL, *silent)
	if err != nil { fmt.Fprintf(os.Stderr, "\033[91m[-]\033[0m output error: %s\n", err); os.Exit(1) }
	defer rep.Close()

	if !*silent {
		fmt.Fprintf(os.Stderr, "  \033[96m[*]\033[0m Probing \033[1m%d\033[0m target(s)  threads:\033[1m%d\033[0m\n\n", len(urls), *c)
	}

	ch := make(chan string, len(urls))
	var wg sync.WaitGroup
	for i := 0; i < *c; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rawURL := range ch {
				r := probe.Do(rawURL, opts)
				res := &reporter.Result{
					URL:           r.URL,
					FinalURL:      r.FinalURL,
					StatusCode:    r.StatusCode,
					Title:         r.Title,
					ContentLength: r.ContentLength,
					Server:        r.Server,
					Words:         r.Words,
					Lines:         r.Lines,
					Tech:          r.Tech,
					WAF:           r.WAF,
					FaviconHash:   r.FaviconHash,
					FaviconApp:    r.FaviconApp,
					Error:         r.Error,
				}
				if r.TLS != nil {
					res.TLSGrade   = r.TLS.Grade
					res.TLSVersion = r.TLS.Version
					res.TLSExpiry  = r.TLS.Expiry
					res.TLSDaysLeft= r.TLS.DaysLeft
				}

				if *er && res.Error != "" { continue }
				if len(matchSC)  > 0 && !matchSC[res.StatusCode]   { continue }
				if len(filterSC) > 0 && filterSC[res.StatusCode]    { continue }
				if *ms >= 0 && int(res.ContentLength) != *ms         { continue }
				if *fs >= 0 && int(res.ContentLength) == *fs         { continue }
				if *mt != "" && !strings.Contains(strings.ToLower(res.Title), strings.ToLower(*mt)) { continue }
				if *ft != "" &&  strings.Contains(strings.ToLower(res.Title), strings.ToLower(*ft)) { continue }

				rep.Print(res)
			}
		}()
	}
	for _, rawURL := range urls { ch <- rawURL }
	close(ch)
	wg.Wait()

	if *outJSON != "" {
		if err := rep.SaveJSON(*outJSON); err != nil {
			fmt.Fprintf(os.Stderr, "\033[91m[-]\033[0m JSON save: %s\n", err)
		} else if !*silent {
			fmt.Fprintf(os.Stderr, "  \033[92m[+]\033[0m Saved → %s\n", *outJSON)
		}
	}
	rep.Summary()
}

func parseCodes(s string) map[int]bool {
	m := map[int]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p == "" { continue }
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil { m[n] = true }
	}
	return m
}
