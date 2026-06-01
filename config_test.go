package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// config tests verify that DefaultConfig returns sane values, that LoadConfig
// falls back gracefully on missing files, and that SaveConfig + LoadConfig
// form a clean roundtrip, if those break, every run that touches the config
// file will silently use wrong settings.

func TestDefaultConfig_SaneDefaults(t *testing.T) {
	c := DefaultConfig()
	if c == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	if c.ConcurrentWorkers <= 0 {
		t.Errorf("ConcurrentWorkers = %d, want > 0", c.ConcurrentWorkers)
	}
	if c.RequestRate <= 0 {
		t.Errorf("RequestRate = %d, want > 0", c.RequestRate)
	}
	if c.ProxyTestTimeout <= 0 {
		t.Errorf("ProxyTestTimeout = %d, want > 0", c.ProxyTestTimeout)
	}
	if c.TimeoutSettings.Connection <= 0 {
		t.Errorf("TimeoutSettings.Connection = %v, want > 0", c.TimeoutSettings.Connection)
	}
	if c.BypassSettings.MinDelay <= 0 {
		t.Errorf("BypassSettings.MinDelay = %v, want > 0", c.BypassSettings.MinDelay)
	}
	if c.BypassSettings.MaxDelay <= c.BypassSettings.MinDelay {
		t.Errorf("MaxDelay (%v) should be greater than MinDelay (%v)",
			c.BypassSettings.MaxDelay, c.BypassSettings.MinDelay)
	}
	if len(c.BypassSettings.StatusCodeTriggers) == 0 {
		t.Error("StatusCodeTriggers should not be empty")
	}
}

func TestDefaultConfig_Has429Trigger(t *testing.T) {
	c := DefaultConfig()
	found := false
	for _, code := range c.BypassSettings.StatusCodeTriggers {
		if code == 429 {
			found = true
		}
	}
	if !found {
		t.Error("StatusCodeTriggers should include 429 (Too Many Requests)")
	}
}

func TestLoadConfig_EmptyPath_ReturnsDefault(t *testing.T) {
	c, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig('') unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("LoadConfig('') returned nil config")
	}
	// spot-check a default value
	def := DefaultConfig()
	if c.ConcurrentWorkers != def.ConcurrentWorkers {
		t.Errorf("ConcurrentWorkers = %d, want %d", c.ConcurrentWorkers, def.ConcurrentWorkers)
	}
}

func TestLoadConfig_MissingFile_ReturnsDefault(t *testing.T) {
	c, err := LoadConfig("/tmp/nonexistent_demon_config_xyz.json")
	// it returns the default config even on error (graceful fallback)
	if c == nil {
		t.Fatal("LoadConfig with missing file returned nil config")
	}
	_ = err // error is expected but not fatal
}

func TestSaveAndLoadConfig_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/demon_config_test.json"

	original := DefaultConfig()
	original.ConcurrentWorkers = 42
	original.RequestRate = 777
	original.TimeoutSettings.Connection = 15 * time.Second

	if err := original.SaveConfig(path); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig after save: %v", err)
	}

	if loaded.ConcurrentWorkers != 42 {
		t.Errorf("ConcurrentWorkers = %d, want 42", loaded.ConcurrentWorkers)
	}
	if loaded.RequestRate != 777 {
		t.Errorf("RequestRate = %d, want 777", loaded.RequestRate)
	}
	if loaded.TimeoutSettings.Connection != 15*time.Second {
		t.Errorf("TimeoutSettings.Connection = %v, want 15s", loaded.TimeoutSettings.Connection)
	}
}

func TestSaveConfig_ProducesValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/check_json.json"

	if err := DefaultConfig().SaveConfig(path); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Errorf("saved config is not valid JSON: %v", err)
	}
}
