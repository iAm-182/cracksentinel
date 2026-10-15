package mcpclient

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

type Client struct {
	cmd    *exec.Cmd
	stdin  *bufio.Writer
	stdout *bufio.Scanner
	mu     sync.Mutex
	nextID int
	closed bool
}

type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

func Spawn(command []string, env []string, timeout time.Duration) (*Client, error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	cmd := exec.Command(command[0], command[1:]...)
	if len(env) > 0 {
		cmd.Env = append(osEnviron(), env...)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &Client{
		cmd:    cmd,
		stdin:  bufio.NewWriter(stdin),
		stdout: bufio.NewScanner(stdout),
		nextID: 1,
	}
	c.stdout.Buffer(make([]byte, 1<<20), 64<<20)
	go func() {
		time.Sleep(timeout)
		c.Close()
	}()
	return c, nil
}

func osEnviron() []string {
	return environList()
}

func (c *Client) Initialize(name string) error {
	_, err := c.Call("initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": name, "version": "1.0.0"},
	})
	if err != nil {
		return err
	}
	return c.Notify("notifications/initialized")
}

func (c *Client) ListTools() ([]Tool, error) {
	res, err := c.Call("tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var out struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(res, &out); err != nil {
		return nil, err
	}
	return out.Tools, nil
}

func (c *Client) Call(method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, fmt.Errorf("client closed")
	}
	id := c.nextID
	c.nextID++
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := c.stdin.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	if err := c.stdin.Flush(); err != nil {
		return nil, err
	}
	for {
		if !c.stdout.Scan() {
			if err := c.stdout.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("server closed stream")
		}
		var msg map[string]json.RawMessage
		if err := json.Unmarshal(c.stdout.Bytes(), &msg); err != nil {
			continue
		}
		idRaw, ok := msg["id"]
		if !ok {
			continue
		}
		var gotID int
		if err := json.Unmarshal(idRaw, &gotID); err != nil {
			continue
		}
		if gotID != id {
			continue
		}
		if errRaw, ok := msg["error"]; ok {
			var e struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			json.Unmarshal(errRaw, &e)
			return nil, fmt.Errorf("rpc error %d: %s", e.Code, e.Message)
		}
		return msg["result"], nil
	}
}

func (c *Client) CallTool(name string, args map[string]any) (json.RawMessage, error) {
	return c.Call("tools/call", map[string]any{"name": name, "arguments": args})
}

func (c *Client) CallToolText(name string, args map[string]any) (string, error) {
	res, err := c.CallTool(name, args)
	if err != nil {
		return "", err
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(res, &out); err != nil {
		return "", err
	}
	if out.IsError && len(out.Content) > 0 {
		return out.Content[0].Text, fmt.Errorf("tool error")
	}
	var sb []byte
	for _, c := range out.Content {
		if c.Type == "text" {
			sb = append(sb, []byte(c.Text)...)
			sb = append(sb, '\n')
		}
	}
	return string(sb), nil
}

func (c *Client) Notify(method string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return fmt.Errorf("client closed")
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": map[string]any{}})
	c.stdin.Write(append(b, '\n'))
	return c.stdin.Flush()
}

func (c *Client) FindTool(substr string) *Tool {
	tools, err := c.ListTools()
	if err != nil {
		return nil
	}
	for _, t := range tools {
		if containsFold(t.Name, substr) {
			tt := t
			return &tt
		}
	}
	return nil
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	if c.cmd.Process != nil {
		c.cmd.Process.Kill()
	}
}

func containsFold(s, sub string) bool {
	return len(sub) == 0 || indexFold(s, sub) >= 0
}

func indexFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if 'A' <= a && a <= 'Z' {
				a += 32
			}
			if 'A' <= b && b <= 'Z' {
				b += 32
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

var _ = strconv.Itoa
