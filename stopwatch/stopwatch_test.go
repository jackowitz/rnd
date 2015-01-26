package stopwatch

import (
	"fmt"
	"time"
)

func ExampleStopwatch() {
	s := NewStopwatch()
	s.Start()

	delay := 3*time.Second
	time.Sleep(delay)
	s.Stop("Sleep")

	s.laps["Sleep"] = delay
	fmt.Println(s)
	// Output:
	// Sleep: 3s
}
