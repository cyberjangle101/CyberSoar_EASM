// Command democap captures the screenshots and video frames of the README and the demo video
// from a running agent, normally the UAT lab's made-up company (acme-corp.test: see uat_lab_test.go
// and docs/DEMO.md). It drives headless Chrome or Edge over the DevTools protocol.
//
//	EASM_DEMO_COOKIE="easm_session=..." go run ./tools/democap -script docs/demo/script.txt -out docs/images
//
// The session cookie is read from the environment so it never appears on a command line. Each line
// of the script is one step:
//
//	shot  <name> <path> [light|dark] [scrollY]   one PNG of the page, <name>.png
//	clip  <name> <path> [light|dark] <frames> <scrollTo>   frames scrolling down to scrollTo, <name>-NNN.png
//	card  <name> <html file> <fragment>   a title card: a local HTML file given its text in the fragment
//
// Lines starting with # are comments.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

func main() {
	base := flag.String("base", "http://127.0.0.1:18100", "the agent to capture")
	script := flag.String("script", "docs/demo/script.txt", "capture steps")
	out := flag.String("out", "docs/images", "where the PNG files go")
	width := flag.Int("width", 1440, "viewport width")
	height := flag.Int("height", 900, "viewport height")
	browser := flag.String("browser", "", "Chrome or Edge (default: the usual install locations)")
	flag.Parse()

	exe := *browser
	if exe == "" {
		exe = findBrowser()
	}
	if exe == "" {
		log.Fatal("no Chrome or Edge found; pass -browser")
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		log.Fatal(err)
	}
	profile, err := os.MkdirTemp("", "democap-")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(profile) }()
	const port = "9339"
	cmd := exec.Command(exe, "--headless=new", "--remote-debugging-port="+port, "--user-data-dir="+profile, //nolint:gosec // G204: a local browser for a local capture
		"--remote-allow-origins=http://127.0.0.1", "--no-first-run", "--hide-scrollbars", "--force-device-scale-factor=1", "about:blank")
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	stopBrowser = func() { _ = cmd.Process.Kill() }
	defer stopBrowser()

	c, err := connect("http://127.0.0.1:" + port)
	if err != nil {
		fatal(err)
	}
	u, _ := url.Parse(*base)
	for _, kv := range strings.Split(os.Getenv("EASM_DEMO_COOKIE"), ";") {
		if name, value, ok := strings.Cut(strings.TrimSpace(kv), "="); ok {
			c.call("Network.setCookie", map[string]any{"name": name, "value": value, "domain": u.Hostname(), "path": "/"})
		}
	}
	c.call("Emulation.setDeviceMetricsOverride", map[string]any{"width": *width, "height": *height, "deviceScaleFactor": 1, "mobile": false})

	f, err := os.Open(*script)
	if err != nil {
		fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		w := strings.Fields(line)
		switch w[0] {
		case "shot":
			c.open(u, w[2], arg(w, 3, "light"))
			if y := atoi(arg(w, 4, "0")); y > 0 {
				c.scroll(y)
			}
			c.save(filepath.Join(*out, w[1]+".png"))
		case "clip":
			c.open(u, w[2], arg(w, 3, "light"))
			n, to := atoi(arg(w, 4, "30")), atoi(arg(w, 5, "0"))
			for i := 0; i < n; i++ {
				c.scroll(to * i / max(n-1, 1))
				c.save(filepath.Join(*out, fmt.Sprintf("%s-%03d.png", w[1], i)))
			}
		case "card":
			abs, _ := filepath.Abs(w[2])
			c.navigate("file:///" + filepath.ToSlash(abs) + "#" + arg(w, 3, ""))
			c.save(filepath.Join(*out, w[1]+".png"))
		default:
			fatalf("unknown step %q", w[0])
		}
		fmt.Println("done:", line)
	}
	if err := sc.Err(); err != nil {
		fatal(err)
	}
}

// stopBrowser ends the headless browser; fatal calls it so no browser is left running.
var stopBrowser = func() {}

func fatal(v ...any) {
	stopBrowser()
	log.Fatal(v...)
}

func fatalf(format string, v ...any) {
	stopBrowser()
	log.Fatalf(format, v...)
}

func arg(w []string, i int, def string) string {
	if i < len(w) {
		return w[i]
	}
	return def
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func findBrowser() string {
	for _, p := range []string{
		os.Getenv("ProgramFiles") + `\Google\Chrome\Application\chrome.exe`,
		os.Getenv("ProgramFiles(x86)") + `\Microsoft\Edge\Application\msedge.exe`,
		"/usr/bin/google-chrome", "/usr/bin/chromium", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// cdp is one DevTools page session.
type cdp struct {
	ws     *websocket.Conn
	mu     sync.Mutex
	nextID int
}

func connect(devtools string) (*cdp, error) {
	var target struct{ WebSocketDebuggerURL string }
	for i := 0; i < 50; i++ {
		req, _ := http.NewRequest(http.MethodPut, devtools+"/json/new?about:blank", nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if json.Unmarshal(b, &target) == nil && target.WebSocketDebuggerURL != "" {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if target.WebSocketDebuggerURL == "" {
		return nil, errors.New("the browser's DevTools endpoint did not answer")
	}
	ws, err := websocket.Dial(target.WebSocketDebuggerURL, "", "http://127.0.0.1")
	if err != nil {
		return nil, err
	}
	ws.MaxPayloadBytes = 64 << 20
	c := &cdp{ws: ws}
	c.call("Page.enable", nil)
	c.call("Network.enable", nil)
	return c, nil
}

// call sends one command and returns its result, skipping the events in between.
func (c *cdp) call(method string, params any) json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	id := c.nextID
	if err := websocket.JSON.Send(c.ws, map[string]any{"id": id, "method": method, "params": params}); err != nil {
		fatalf("%s: %v", method, err)
	}
	for {
		var m struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct{ Message string }
		}
		if err := websocket.JSON.Receive(c.ws, &m); err != nil {
			fatalf("%s: %v", method, err)
		}
		if m.ID != id {
			continue
		}
		if m.Error != nil {
			fatalf("%s: %s", method, m.Error.Message)
		}
		return m.Result
	}
}

func (c *cdp) navigate(u string) {
	c.call("Page.navigate", map[string]any{"url": u})
	for i := 0; i < 100; i++ { // wait for the page to finish loading
		var r struct{ Result struct{ Value string } }
		_ = json.Unmarshal(c.call("Runtime.evaluate", map[string]any{"expression": "document.readyState", "returnByValue": true}), &r)
		if r.Result.Value == "complete" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(400 * time.Millisecond) // fonts and the progress script
}

// open loads a page of the agent in the given theme (the theme cookie the top-bar toggle sets).
func (c *cdp) open(base *url.URL, path, theme string) {
	c.call("Network.setCookie", map[string]any{"name": "easm_theme", "value": theme, "domain": base.Hostname(), "path": "/"})
	c.navigate(strings.TrimSuffix(base.String(), "/") + path)
}

func (c *cdp) scroll(y int) {
	c.call("Runtime.evaluate", map[string]any{"expression": fmt.Sprintf("window.scrollTo(0,%d)", y)})
	time.Sleep(60 * time.Millisecond)
}

func (c *cdp) save(path string) {
	var r struct{ Data string }
	if err := json.Unmarshal(c.call("Page.captureScreenshot", map[string]any{"format": "png"}), &r); err != nil {
		fatal(err)
	}
	b, err := base64.StdEncoding.DecodeString(r.Data)
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		fatal(err)
	}
}
