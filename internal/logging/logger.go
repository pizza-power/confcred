package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

var (
	globalLogger *slog.Logger
	mu           sync.RWMutex
	logFile      *os.File
)

func Init(logFilePath string, verbose bool) error {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	var writers []io.Writer

	consoleWriter := os.Stderr
	writers = append(writers, consoleWriter)

	if logFilePath != "" {
		f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		logFile = f
		writers = append(writers, f)
	}

	multiWriter := io.MultiWriter(writers...)

	handler := slog.NewJSONHandler(multiWriter, &slog.HandlerOptions{
		Level: level,
	})

	globalLogger = slog.New(handler)
	return nil
}

func Close() {
	if logFile != nil {
		logFile.Close()
	}
}

func Get() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	if globalLogger == nil {
		return slog.Default()
	}
	return globalLogger
}

// MaskValue shows first 4 and last 4 chars of a sensitive value,
// replacing the middle with asterisks. Short values are fully masked.
func MaskValue(val string) string {
	val = strings.TrimSpace(val)
	if len(val) <= 8 {
		return strings.Repeat("*", len(val))
	}
	return val[:4] + strings.Repeat("*", len(val)-8) + val[len(val)-4:]
}
