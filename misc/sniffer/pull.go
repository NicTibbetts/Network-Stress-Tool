package main

import (
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
	"strings"
	"regexp"
	"encoding/hex"
	"time"
    "os/exec"
    "runtime"
    "encoding/csv"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"

    "golang.org/x/term"

)

// Global variables for command-line arguments
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	//orange
	colorOrange = "\033[38;5;208m"
)
var (
    device  string
    srcIP   string
    dstIP   string
    srcPort string
    dstPort string
    verbose bool
)

func clearScreen() {
    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.Command("cmd", "/c", "cls")
    } else {
        cmd = exec.Command("clear")
    }
    cmd.Stdout = os.Stdout
    cmd.Run()
}

func printHelp() {
    fmt.Println(`Packet Sniffer Tool Usage:
-device <device_name>    Network device to capture traffic on (e.g., 'en0')
-srcIP <source_ip>       Source IP address to filter
-dstIP <destination_ip>  Destination IP address to filter
-srcPort <source_port>   Source port to filter
-dstPort <destination_port> Destination port to filter
-verbose                 Enable verbose output

Examples:
o run *.go --device en0 --srcIP 10.0.1.94 -verbose
sudo go run *.go --device en0 --srcIP 192.168.1.105 --dstIP 192.168.1.105
sudo go run *.go --device en0 --srcIP 192.168.1.105 --dstIP 192.168.1.105 --srcPort 80 --dstPort 80
go run *.go --device en0 --srcIP 10.0.1.94 -h

Use '-h' or '--help' to display this help message.`)
    os.Exit(0)
}

func main() {
	for _, arg := range os.Args[1:] {
        if arg == "-h" || arg == "--help" {
            printHelp()
        }
    }
    // Parse command-line arguments
    parseFlags()

    // Open device for capturing
    handle, err := pcap.OpenLive(device, 262144, true, pcap.BlockForever) // Increased snapshot length
    if err != nil {
        log.Fatalf("Could not open device %s: %v", device, err)
    }
    defer handle.Close()

    // Construct and apply BPF filter
    applyBPFFilter(handle)

    // Create a packet source
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    packetSource.NoCopy = true // Improve performance by avoiding packet data copies
    packetChan := packetSource.Packets()

    // Set up signal handling
    signalChannel := make(chan os.Signal, 1)
    signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)

       // Open a CSV file for writing
       csvFile, err := os.Create("captured_packets.csv")
       if err != nil {
           log.Fatalf("Could not create CSV file: %v", err)
       }
       defer csvFile.Close()
   
       writer := csv.NewWriter(csvFile)
       defer writer.Flush()
   
       // Write CSV header
       header := []string{"Timestamp", "IP Src", "IP Dst", "Protocol", "Src Port", "Dst Port", "Seq Number"}
       if err := writer.Write(header); err != nil {
           log.Fatalf("Error writing header to CSV file: %v", err)
       }
   
       // Modify startWorkerPool function to accept the CSV writer
       startWorkerPool(packetChan, signalChannel, writer)
}

func parseFlags() {
    flag.StringVar(&device, "device", "en0", "Network device to capture traffic on (e.g., 'en0')")
    flag.StringVar(&srcIP, "srcIP", "", "Source IP address to filter")
    flag.StringVar(&dstIP, "dstIP", "", "Destination IP address to filter")
    flag.StringVar(&srcPort, "srcPort", "", "Source port to filter")
    flag.StringVar(&dstPort, "dstPort", "", "Destination port to filter")
    flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
    flag.Parse()
}

func applyBPFFilter(handle *pcap.Handle) {
    // Construct BPF filter from command-line arguments
    bpfFilter := constructBPFFilter(srcIP, dstIP, srcPort, dstPort)
    if verbose && bpfFilter != "" {
        fmt.Printf("Using filter: %s\n", bpfFilter)
    } else if bpfFilter == "" && verbose {
        fmt.Println("Capturing all traffic without filters")
    }

    // Apply BPF filter
    if bpfFilter != "" {
        if err := handle.SetBPFFilter(bpfFilter); err != nil {
            log.Fatalf("Could not set BPF filter: %v", err)
        }
    }
}

func startWorkerPool(packetChan <-chan gopacket.Packet, signalChannel chan os.Signal, writer *csv.Writer) {
    // Define the number of workers
    const numWorkers = 10

    // Create a channel for distributing packets to workers
    workChan := make(chan gopacket.Packet, 100) // Buffered channel

    // Worker function
    worker := func(id int, packets <-chan gopacket.Packet) {
        for packet := range packets {
            analyzePacket(packet, verbose, writer)
        }
    }
    // Start a fixed number of worker goroutines
    for i := 0; i < numWorkers; i++ {
        go worker(i, workChan)
    }

    // Distribute packets to workers or handle signals
    for {
        select {
        case packet := <-packetChan:
            workChan <- packet
        case <-signalChannel:
            fmt.Println("\nCapture interrupted by user.")
            return
        }
    }
}


func constructBPFFilter(srcIP, dstIP, srcPort, dstPort string) string {
    var filters []string
    if srcIP != "" {
        filters = append(filters, fmt.Sprintf("src host %s", srcIP))
    }
    if dstIP != "" {
        filters = append(filters, fmt.Sprintf("dst host %s", dstIP))
    }
    if srcPort != "" {
        filters = append(filters, fmt.Sprintf("src port %s", srcPort))
    }
    if dstPort != "" {
        filters = append(filters, fmt.Sprintf("dst port %s", dstPort))
    }
    return strings.Join(filters, " and ")
}




func colorize(color string, message string) string {
	return fmt.Sprintf("%s%s%s", color, message, colorReset)
}

func analyzePacket(packet gopacket.Packet, verbose bool, writer *csv.Writer) {
    clearScreen()
    // Print packet metadata if verbose is enabled
    if verbose {
        fmt.Println(colorize(colorYellow, "New packet captured:"))
        metadata := packet.Metadata()
        if metadata != nil {
            fmt.Printf("Timestamp: %s, Capture Length: %s, Packet Length: %s\n",
                colorize(colorGreen, metadata.Timestamp.Format("2006-01-02 15:04:05.000000")),
                colorize(colorCyan, fmt.Sprintf("%d", metadata.CaptureLength)),
                colorize(colorCyan, fmt.Sprintf("%d", metadata.Length)))
        }
    }

    // IP layer details
    ipLayer := packet.NetworkLayer()
    if ipLayer != nil {
        src, dst := ipLayer.NetworkFlow().Endpoints()
        fmt.Printf("IP Src: %s, IP Dst: %s\n",
            colorize(colorRed, src.String()),
            colorize(colorRed, dst.String()))
    }

    // TCP layer details
    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer != nil {
        tcp, _ := tcpLayer.(*layers.TCP)
        fmt.Printf("TCP Src Port: %s, Dst Port: %s, Seq: %s\n",
            colorize(colorPurple, fmt.Sprintf("%d", tcp.SrcPort)),
            colorize(colorPurple, fmt.Sprintf("%d", tcp.DstPort)),
            colorize(colorWhite, fmt.Sprintf("%d", tcp.Seq)))
    }

    // UDP layer details
    udpLayer := packet.Layer(layers.LayerTypeUDP)
    if udpLayer != nil {
        udp, _ := udpLayer.(*layers.UDP)
        fmt.Printf("UDP Src Port: %s, Dst Port: %s\n",
            colorize(colorOrange, fmt.Sprintf("%d", udp.SrcPort)),
            colorize(colorOrange, fmt.Sprintf("%d", udp.DstPort)))
    }

    // Application layer details and payload hex dump
    applicationLayer := packet.ApplicationLayer()
    if applicationLayer != nil {
        if isHTTP(applicationLayer.Payload()) {
            fmt.Println("HTTP Payload detected:")
            fmt.Printf("%s\n", applicationLayer.Payload())
        } else {
            // fmt.Println("Payload (Hex Dump):")
            printHexDump(applicationLayer.Payload())
        }
    }
    //  else {
    //     // For non-application layer packets, attempt to print any available payload as hex dump
    //     layerPayload := packet.Data()
    //     if len(layerPayload) > 0 {
    //         fmt.Println("Payload (Hex Dump):")
    //         printHexDump(layerPayload)
    //     }
    // }

    // Add a separator for clarity between packets
    // fmt.Println(strings.Repeat("-", 80))
    
    time.Sleep(1 * time.Second) // Wait!

}


func printHexDump(payload []byte) {
    if len(payload) == 0 {
        fmt.Println("No payload data to display.")
        return
    }

    // Prepend the message to the hex dump
    dump := "Payload (Hex Dump):\n" + hex.Dump(payload)

    // Get the current terminal width
    width, _, err := term.GetSize(0)
    if err != nil {
        // Default to 80 characters if terminal size cannot be determined
        width = 80
    }

    // Split the dump by newline to process each line individually
    lines := strings.Split(dump, "\n")
    for _, line := range lines {
        // Calculate the padding needed for alignment
        padding := width - len(line) - 1 // -1 for the newline character
        if padding > 0 {
            fmt.Print(strings.Repeat(" ", padding))
        }
        fmt.Println(line)
    }
}


// isHTTP checks if a packet payload is likely to be HTTP based on a simple heuristic
func isHTTP(payload []byte) bool {
    // A very basic check for HTTP request methods in the payload
    pattern := regexp.MustCompile(`(?i)^(GET|POST|HEAD|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) [^ ]+ HTTP/1\.[01]`)
    return pattern.Match(payload)
}

