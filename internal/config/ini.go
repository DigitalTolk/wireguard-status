package config

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"time"
)

// section is one [Header] block with its key/value lines, in file order.
type section struct {
	name string            // as written, e.g. "Peer"
	keys map[string]string // lower-cased key -> raw value
	line int               // 1-based line of the header, for error messages
}

// parseSections tokenises a WireGuard-style INI file: [Section] headers, then
// "Key = Value" lines. Blank lines and lines starting with '#' or ';' are
// ignored. Repeated sections (e.g. multiple [Peer]) are preserved in order.
func parseSections(b []byte) ([]section, error) {
	var (
		out []section
		cur *section
	)
	sc := bufio.NewScanner(bytes.NewReader(b))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("line %d: malformed section header %q", lineNo, line)
			}
			name := strings.TrimSpace(line[1 : len(line)-1])
			if name == "" {
				return nil, fmt.Errorf("line %d: empty section header", lineNo)
			}
			out = append(out, section{name: name, keys: map[string]string{}, line: lineNo})
			cur = &out[len(out)-1]
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected \"Key = Value\", got %q", lineNo, line)
		}
		if cur == nil {
			return nil, fmt.Errorf("line %d: key %q before any [Section]", lineNo, strings.TrimSpace(k))
		}
		cur.keys[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Config) parseINI(b []byte) error {
	sections, err := parseSections(b)
	if err != nil {
		return err
	}
	for _, s := range sections {
		var err error
		switch strings.ToLower(s.name) {
		case "server":
			err = c.applyServer(s)
		case "auth":
			err = c.applyAuth(s)
		case "monitor":
			err = c.applyMonitor(s)
		default:
			err = fmt.Errorf("unknown section [%s]", s.name)
		}
		if err != nil {
			return fmt.Errorf("line %d [%s]: %w", s.line, s.name, err)
		}
	}
	return nil
}

func (c *Config) applyServer(s section) error {
	for k, v := range s.keys {
		switch k {
		case "listen":
			c.Listen = v
		case "collector":
			c.Collector = v
		case "tlscert":
			c.TLSCert = v
		case "tlskey":
			c.TLSKey = v
		case "pollinterval":
			d, err := time.ParseDuration(v)
			if err != nil {
				return fmt.Errorf("PollInterval: %w", err)
			}
			c.PollInterval = Duration(d)
		default:
			return fmt.Errorf("unknown key %q", k)
		}
	}
	return nil
}

func (c *Config) applyAuth(s section) error {
	for k, v := range s.keys {
		switch k {
		case "username":
			c.Auth.Username = v
		case "password":
			c.Auth.Password = v
		case "passwordhash":
			c.Auth.PasswordHash = v
		default:
			return fmt.Errorf("unknown key %q", k)
		}
	}
	return nil
}

func (c *Config) applyMonitor(s section) error {
	for k, v := range s.keys {
		switch k {
		case "handshakestale":
			d, err := time.ParseDuration(v)
			if err != nil {
				return fmt.Errorf("HandshakeStale: %w", err)
			}
			c.Thresholds.HandshakeStale = Duration(d)
		default:
			return fmt.Errorf("unknown key %q", k)
		}
	}
	return nil
}
