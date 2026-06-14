go run *.go --device <your_network_device> --srcIP <source_ip> --dstIP <destination_ip> --srcPort <source_port> --dstPort <destination_port>

Examples:
sudo go run *.go --device en0 --srcIP 10.0.1.1
go run *.go --device en0 --srcIP 10.0.1.94 --dstIP 3.163.165.76
sudo go run *.go --device en0 --srcIP 192.168.1.105 --dstIP 192.168.1.105 --srcPort 80 --dstPort 80
sudo go run *.go --device en0 --srcIP 192.168.1.105 --dstIP 192.168.1.105
