package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
)

func main() {
	var port string
	flag.StringVar(&port, "port", "8080", "Set the port on which the commander listens")
	flag.Parse()

	address := fmt.Sprintf(":%s", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Printf("Error listening: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("Listening on %s\n", address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Error accepting: %v\n", err)
			continue
		}
		fmt.Printf("Drone connected: %s\n", conn.RemoteAddr().String())
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Create a goroutine to handle incoming drone responses
	go func() {
		reader := bufio.NewReader(conn)
		for {
			message, err := reader.ReadString('\n')
			if err != nil {
				fmt.Println("Error reading drone response:", err)
				return // or handle the error as appropriate
			}
			fmt.Print("Drone response: " + message)
		}
	}()

	// Main loop for reading and sending commands to the drone
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("Enter command: ")
		if scanner.Scan() {
			text := scanner.Text()
			// Stop command handling
			if strings.TrimSpace(text) == "stop" {
				fmt.Println("Stopping command input.")

				return

			}
			_, err := conn.Write([]byte(text + "\n"))
			if err != nil {
				fmt.Println("Error sending command to drone:", err)
				return // or handle the error as appropriate
			}
		}
	}
}
