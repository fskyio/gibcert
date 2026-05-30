// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 FSKY <development@fsky.io>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

type Logger struct {
	logger *slog.Logger
	closer io.Closer
}

type Options struct {
	Format string
	Syslog bool
	Stderr io.Writer
}

func New(opts Options) (*Logger, error) {
	out := opts.Stderr
	if out == nil {
		out = os.Stderr
	}
	var closer io.Closer
	if opts.Syslog {
		w, err := openSyslog("gibcert")
		if err != nil {
			return nil, fmt.Errorf("open syslog: %w", err)
		}
		closer = w
		out = io.MultiWriter(out, w)
	}

	var handler slog.Handler
	switch opts.Format {
	case "", "text":
		handler = slog.NewTextHandler(out, &slog.HandlerOptions{})
	case "json":
		handler = slog.NewJSONHandler(out, &slog.HandlerOptions{})
	default:
		if closer != nil {
			_ = closer.Close()
		}
		return nil, fmt.Errorf("unsupported log format %q", opts.Format)
	}
	return &Logger{logger: slog.New(handler), closer: closer}, nil
}

func (l *Logger) Close() error {
	if l == nil || l.closer == nil {
		return nil
	}
	return l.closer.Close()
}

func (l *Logger) Error(msg string, attrs ...any) {
	if l == nil || l.logger == nil {
		fmt.Fprintln(os.Stderr, "gibcert:", msg)
		return
	}
	l.logger.Error(msg, attrs...)
}

func (l *Logger) Info(msg string, attrs ...any) {
	if l == nil || l.logger == nil {
		fmt.Fprintln(os.Stderr, msg)
		return
	}
	l.logger.Info(msg, attrs...)
}

func (l *Logger) Warn(msg string, attrs ...any) {
	if l == nil || l.logger == nil {
		fmt.Fprintln(os.Stderr, "gibcert:", msg)
		return
	}
	l.logger.Warn(msg, attrs...)
}
