package stopwatch

import (
	"bytes"
	"fmt"
	"time"
)

type Stopwatch struct {
	last time.Time
	laps map[string]time.Duration
}

func NewStopwatch() *Stopwatch {
	zero := time.Time{}
	laps := make(map[string]time.Duration)
	return &Stopwatch{ zero, laps }
}

func (s *Stopwatch) Start() {
	s.last = time.Now()
}

func (s *Stopwatch) Stop(label string) {
	s.laps[label] = time.Since(s.last)
}

func (s *Stopwatch) String() string {
	var b bytes.Buffer
	for label, dur := range s.laps {
		b.WriteString(fmt.Sprintf("%s: %s\n", label, dur))
	}
	return b.String()
}
