package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type Reporter struct {
	mu      sync.Mutex
	Results []*Result
	start   time.Time
	fJSON   *os.File
	fTXT    *os.File
	fJSONL  *os.File
	silent  bool
}

type Result struct {
	URL           string
	FinalURL      string
	StatusCode    int
	Title         string
	ContentLength int64
	Server        string
	Words         int
	Lines         int
	Tech          []string
	WAF           string
	TLSGrade      string
	TLSVersion    string
	TLSExpiry     string
	TLSDaysLeft   int
	FaviconHash   string
	FaviconApp    string
	Error         string
}

func New(jsonOut, txtOut, jsonlOut string, silent bool) (*Reporter, error) {
	r := &Reporter{start: time.Now(), silent: silent}
	open := func(p string) (*os.File, error) {
		if p == "" { return nil, nil }
		return os.Create(p)
	}
	var err error
	if r.fJSON,  err = open(jsonOut);  err != nil { return nil, err }
	if r.fTXT,   err = open(txtOut);   err != nil { return nil, err }
	if r.fJSONL, err = open(jsonlOut); err != nil { return nil, err }
	return r, nil
}

func (rep *Reporter) Close() {
	for _, f := range []*os.File{rep.fJSON, rep.fTXT, rep.fJSONL} {
		if f != nil { f.Close() }
	}
}

func fmtSize(n int64) string {
	switch {
	case n < 1024:      return fmt.Sprintf("%dB", n)
	case n < 1024*1024: return fmt.Sprintf("%.1fKB", float64(n)/1024)
	default:            return fmt.Sprintf("%.1fMB", float64(n)/1024/1024)
	}
}

func scCol(code int) string {
	switch {
	case code >= 200 && code < 300: return "\033[92m\033[1m"
	case code >= 300 && code < 400: return "\033[93m\033[1m"
	case code == 401 || code == 403: return "\033[91m\033[1m"
	case code >= 400: return "\033[93m"
	case code >= 500: return "\033[91m\033[1m"
	default: return "\033[97m"
	}
}

func (rep *Reporter) Print(r *Result) {
	rep.mu.Lock()
	defer rep.mu.Unlock()
	rep.Results = append(rep.Results, r)

	if rep.silent {
		if r.Error == "" { fmt.Println(r.FinalURL) }
		return
	}

	if r.Error != "" {
		fmt.Fprintf(os.Stderr, "  \033[91m\033[2m[ERR]\033[0m  \033[2m%s\033[0m\n", r.URL)
		if rep.fTXT != nil { fmt.Fprintln(rep.fTXT, "[ERR] "+r.URL) }
		return
	}

	title := r.Title
	if title == "" { title = "" }

	// Line 1: status + url + size + words + lines + title
	fmt.Fprintf(os.Stderr, "  %s[%d]\033[0m  \033[1m%-65s\033[0m  \033[2m%s\033[0m  \033[2m%dw\033[0m  \033[2m%dl\033[0m  \033[97m%s\033[0m\n",
		scCol(r.StatusCode), r.StatusCode,
		r.FinalURL,
		fmtSize(r.ContentLength),
		r.Words, r.Lines,
		title,
	)

	// Line 2: server + tech + WAF + favicon
	var sub []string
	if r.Server != "" { sub = append(sub, fmt.Sprintf("\033[2m[%s]\033[0m", r.Server)) }
	if len(r.Tech) > 0 { sub = append(sub, fmt.Sprintf("\033[96m[%s]\033[0m", strings.Join(r.Tech, ", "))) }
	if r.WAF != "" { sub = append(sub, fmt.Sprintf("\033[91m\033[1m🔥 WAF: %s\033[0m", r.WAF)) }
	if r.FaviconHash != "" {
		fav := r.FaviconHash
		if r.FaviconApp != "" { fav += " → " + r.FaviconApp }
		sub = append(sub, fmt.Sprintf("\033[95m[favicon:%s]\033[0m", fav))
	}
	if len(sub) > 0 {
		fmt.Fprintf(os.Stderr, "       \033[2m↳\033[0m %s\n", strings.Join(sub, "  "))
	}

	// Line 3: TLS
	if r.TLSGrade != "" {
		gc := "\033[92m\033[1m"
		if r.TLSGrade == "B" { gc = "\033[93m" }
		if r.TLSGrade == "C" || r.TLSGrade == "F" { gc = "\033[91m\033[1m" }
		fmt.Fprintf(os.Stderr, "       \033[2m↳ TLS\033[0m %s%s\033[0m  %s  exp:%s (%dd)\n",
			gc, r.TLSGrade, r.TLSVersion, r.TLSExpiry, r.TLSDaysLeft)
	}

	// File output
	if rep.fTXT != nil {
		line := fmt.Sprintf("[%d] %s | %s | %dw %dl", r.StatusCode, r.FinalURL, fmtSize(r.ContentLength), r.Words, r.Lines)
		if r.Title != "" { line += " | " + r.Title }
		if len(r.Tech) > 0 { line += " | tech:" + strings.Join(r.Tech, ",") }
		if r.WAF != "" { line += " | waf:" + r.WAF }
		fmt.Fprintln(rep.fTXT, line)
	}
	if rep.fJSONL != nil {
		b, _ := json.Marshal(r)
		fmt.Fprintln(rep.fJSONL, string(b))
	}
}

func (rep *Reporter) Summary() {
	rep.mu.Lock()
	defer rep.mu.Unlock()
	if rep.silent { return }
	elapsed := time.Since(rep.start)
	cnt     := map[string]int{}
	for _, r := range rep.Results {
		if r.Error != "" { cnt["err"]++; continue }
		switch {
		case r.StatusCode >= 200 && r.StatusCode < 300: cnt["2xx"]++
		case r.StatusCode >= 300 && r.StatusCode < 400: cnt["3xx"]++
		case r.StatusCode >= 400 && r.StatusCode < 500: cnt["4xx"]++
		case r.StatusCode >= 500:                        cnt["5xx"]++
		}
	}
	div := strings.Repeat("─", 56)
	fmt.Fprintf(os.Stderr, "\n  \033[2m%s\033[0m\n", div)
	fmt.Fprintf(os.Stderr, "  \033[92m\033[1m[✓]\033[0m  \033[1m%d\033[0m urls  \033[2m%.1fs\033[0m  \033[92m2xx:%d\033[0m  \033[93m3xx:%d\033[0m  \033[93m4xx:%d\033[0m  \033[91m5xx:%d\033[0m  \033[2merr:%d\033[0m\n",
		len(rep.Results), elapsed.Seconds(), cnt["2xx"], cnt["3xx"], cnt["4xx"], cnt["5xx"], cnt["err"])
	fmt.Fprintf(os.Stderr, "  \033[2m%s\033[0m\n\n", div)
}

func (rep *Reporter) SaveJSON(path string) error {
	rep.mu.Lock()
	defer rep.mu.Unlock()
	f, err := os.Create(path)
	if err != nil { return err }
	defer f.Close()
	b, _ := json.MarshalIndent(rep.Results, "", "  ")
	_, err = f.Write(b)
	return err
}
