package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarning
	LogLevelError
	LogLevelCritical
)

type Logger struct {
	level     LogLevel
	logFile   *os.File
	mu        sync.Mutex
	prefix    string
	timestamp bool
}

func NewLogger(logFile string, level LogLevel) (*Logger, error) {
	var file *os.File
	var err error

	if logFile != "" {
		file, err = os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
	}

	return &Logger{
		level:     level,
		logFile:   file,
		prefix:    "[DEMON]",
		timestamp: true,
	}, nil
}

func (l *Logger) formatMessage(level LogLevel, message string) string {
	var levelText string
	var color ColorAttribute

	switch level {
	case LogLevelDebug:
		levelText = "DEBUG"
		color = ColorWhite
	case LogLevelInfo:
		levelText = "INFO"
		color = ColorGreen
	case LogLevelWarning:
		levelText = "WARNING"
		color = ColorYellow
	case LogLevelError:
		levelText = "ERROR"
		color = ColorRed
	case LogLevelCritical:
		levelText = "CRITICAL"
		color = ColorMagenta
	}

	timestamp := ""
	if l.timestamp {
		timestamp = time.Now().Format("15:04:05") + " "
	}

	return fmt.Sprintf("%s%s[%s] %s%s",
		timestamp,
		l.prefix,
		StyleText(levelText, color),
		message,
		ResetColor())
}

func (l *Logger) log(level LogLevel, message string) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	formatted := l.formatMessage(level, message)

	// Print to console UNLESS the live dashboard owns the screen, a stray log line
	// mid frame scrolls and garbles the in-place redraw. while the dashboard is up,
	// console logging is suppressed and everything still goes to the file below, so
	// nothing is lost; the dashboard itself surfaces live status.
	if !dashboardActive.Load() {
		fmt.Println(formatted)
	}

	// Also log to file if available
	if l.logFile != nil {
		l.logFile.WriteString(formatted + "\n")
		l.logFile.Sync()
	}
}

func (l *Logger) Debug(message string)    { l.log(LogLevelDebug, message) }
func (l *Logger) Info(message string)     { l.log(LogLevelInfo, message) }
func (l *Logger) Warning(message string)  { l.log(LogLevelWarning, message) }
func (l *Logger) Error(message string)    { l.log(LogLevelError, message) }
func (l *Logger) Critical(message string) { l.log(LogLevelCritical, message) }

// SetLevel sets the logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *Logger) Close() {
	if l.logFile != nil {
		l.logFile.Close()
	}
}

// panic recovery wrapper, any goroutine can defer safeGo.recover()
func SafeExecute(fn func(), context string, logger *Logger) {
	defer func() {
		if r := recover(); r != nil {
			if logger != nil {
				logger.Error(fmt.Sprintf("Recovered from panic in %s: %v", context, r))
			} else {
				fmt.Printf("%s Recovered from panic in %s: %v\n", StyleError(""), context, r)
			}
		}
	}()
	fn()
}
