package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LocalVerdict is one verdict from a local (single-user, no GitHub) upload. Like the PostgreSQL
// history it holds the verdict and the rules that fired, never the plan: the plan is identified only
// by its SHA-256, so two uploads of the same plan can be recognized without keeping the plan.
type LocalVerdict struct {
	At             time.Time        `json:"at"`
	PlanSHA256     string           `json:"plan_sha256"`
	Recommendation string           `json:"recommendation"`
	Level          string           `json:"level"`
	Score          int              `json:"score"`
	Findings       []FindingSummary `json:"findings"`
}

// FileHistory keeps the newest LocalVerdicts in a JSON-lines file (mode 0600 in a 0700 directory).
// It is meant for local mode, where one person uses one process; it is not shared between processes.
type FileHistory struct {
	mu    sync.Mutex
	path  string
	max   int
	lines int
}

// OpenFileHistory prepares the file (creating its directory) and keeps at most max verdicts.
func OpenFileHistory(path string, max int) (*FileHistory, error) {
	if path == "" || max < 1 {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, errors.New("create the history folder")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, errors.New("open the history file")
	}
	defer file.Close()
	h := &FileHistory{path: path, max: max}
	entries, _ := readLocalVerdicts(file)
	h.lines = len(entries)
	return h, nil
}

func readLocalVerdicts(file *os.File) ([]LocalVerdict, error) {
	var out []LocalVerdict
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		var v LocalVerdict
		if json.Unmarshal(scanner.Bytes(), &v) == nil && v.Recommendation != "" { // a damaged line is skipped
			out = append(out, v)
		}
	}
	return out, scanner.Err()
}

// Add appends a verdict. When the file holds twice the limit it is rewritten with the newest max.
func (h *FileHistory) Add(v LocalVerdict) error {
	if v.Recommendation == "" || v.Level == "" || v.Score < 0 || v.Score > 100 {
		return ErrInvalid
	}
	if v.At.IsZero() {
		v.At = time.Now().UTC()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(h.path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return errors.New("open the history file")
	}
	_, err = file.Write(append(line, '\n'))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.New("write the history file")
	}
	h.lines++
	if h.lines > 2*h.max {
		return h.trim()
	}
	return nil
}

// trim rewrites the file with the newest max verdicts (write a temp file, then rename).
func (h *FileHistory) trim() error {
	entries, err := h.readAll()
	if err != nil {
		return err
	}
	if len(entries) > h.max {
		entries = entries[len(entries)-h.max:]
	}
	temp, err := os.CreateTemp(filepath.Dir(h.path), ".history-*")
	if err != nil {
		return errors.New("trim the history file")
	}
	defer os.Remove(temp.Name())
	encoder := json.NewEncoder(temp)
	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			temp.Close()
			return errors.New("trim the history file")
		}
	}
	if err := temp.Chmod(0o600); err != nil || temp.Close() != nil {
		return errors.New("trim the history file")
	}
	if err := os.Rename(temp.Name(), h.path); err != nil {
		return errors.New("trim the history file")
	}
	h.lines = len(entries)
	return nil
}

func (h *FileHistory) readAll() ([]LocalVerdict, error) {
	file, err := os.Open(h.path)
	if err != nil {
		return nil, errors.New("read the history file")
	}
	defer file.Close()
	return readLocalVerdicts(file)
}

// List returns up to limit verdicts, newest first.
func (h *FileHistory) List(limit int) ([]LocalVerdict, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	entries, err := h.readAll()
	if err != nil {
		return nil, err
	}
	n := clampLimit(limit)
	out := make([]LocalVerdict, 0, n)
	for i := len(entries) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, entries[i])
	}
	return out, nil
}
