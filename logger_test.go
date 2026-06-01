package main

import (
	"os"
	"strings"
	"testing"
)

// logger tests focus on the level-gate and the formatMessage structure.
// we avoid reading stdout because the log method always prints there;
// instead we test the parts we can control cleanly.

func TestNewLogger_NoFile(t *testing.T) {
	// empty path means console-only, should not error
	l, err := NewLogger("", LogLevelInfo)
	if err != nil {
		t.Fatalf("NewLogger('', LogLevelInfo) unexpected error: %v", err)
	}
	if l == nil {
		t.Fatal("NewLogger returned nil Logger")
	}
	if l.level != LogLevelInfo {
		t.Errorf("level = %v, want LogLevelInfo", l.level)
	}
}

func TestNewLogger_BadPath(t *testing.T) {
	// a path that can't be created should return an error
	_, err := NewLogger("/nonexistent/path/demon_test_logger.log", LogLevelInfo)
	if err == nil {
		t.Error("expected error for unwritable log path, got nil")
	}
}

func TestNewLogger_ValidFile(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "demon_logger_*.log")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	l, err := NewLogger(tmp.Name(), LogLevelDebug)
	if err != nil {
		t.Fatalf("NewLogger with valid file: %v", err)
	}
	defer l.Close()

	// log something and verify the file grows
	l.Info("test message")
	info, _ := os.Stat(tmp.Name())
	if info.Size() == 0 {
		t.Error("log file should be non-empty after logging")
	}
}

func TestSetLevel(t *testing.T) {
	l, _ := NewLogger("", LogLevelCritical)
	l.SetLevel(LogLevelDebug)
	if l.level != LogLevelDebug {
		t.Errorf("after SetLevel(LogLevelDebug), level = %v, want LogLevelDebug", l.level)
	}
}

func TestFormatMessage_ContainsLevelAndText(t *testing.T) {
	l, _ := NewLogger("", LogLevelDebug)

	tests := []struct {
		level   LogLevel
		msg     string
		wantSub string
	}{
		{LogLevelDebug, "debug msg", "debug msg"},
		{LogLevelInfo, "hello info", "hello info"},
		{LogLevelWarning, "watch out", "watch out"},
		{LogLevelError, "boom", "boom"},
	}

	for _, tt := range tests {
		out := l.formatMessage(tt.level, tt.msg)
		if !strings.Contains(out, tt.wantSub) {
			t.Errorf("formatMessage(%v, %q) output %q does not contain %q",
				tt.level, tt.msg, out, tt.wantSub)
		}
		// must also contain the level name somewhere
		levelNames := map[LogLevel]string{
			LogLevelDebug:    "DEBUG",
			LogLevelInfo:     "INFO",
			LogLevelWarning:  "WARNING",
			LogLevelError:    "ERROR",
			LogLevelCritical: "CRITICAL",
		}
		if lname, ok := levelNames[tt.level]; ok {
			if !strings.Contains(out, lname) {
				t.Errorf("formatMessage(%v, %q): output missing level text %q", tt.level, tt.msg, lname)
			}
		}
	}
}

func TestSafeExecute_NoPanic(t *testing.T) {
	l, _ := NewLogger("", LogLevelDebug)
	// should not propagate the panic
	SafeExecute(func() {
		panic("intentional panic for test")
	}, "test context", l)
}

func TestSafeExecute_NormalRun(t *testing.T) {
	l, _ := NewLogger("", LogLevelDebug)
	ran := false
	SafeExecute(func() { ran = true }, "test context", l)
	if !ran {
		t.Error("SafeExecute: the function should have run")
	}
}
