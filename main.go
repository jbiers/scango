package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"

	tcp "github.com/jbiers/scango.git/pkg"
)

// TODO: get **Scanner** class and methods out of main package
type Scanner struct {
	sourceIP    *net.IPAddr
	targetIP    *net.IPAddr
	targetPorts []uint16
}

// send all packets and then wait for the responses
// TODO: make this run in parallel
func (s Scanner) RunScan(t string) {
	// TODO: abstract this away to multiple scan types

	tcpPacket := tcp.TCPHeader{
		Source:         55000,
		Sequence:       rand.Uint32(),
		Acknowledgment: 0,
		DataOffset:     5,
		Reserved:       0,
		ECN:            0,
		Ctrl:           tcp.SYN,
		Window:         0xaaaa,
		Checksum:       0,
		Urgent:         0,
		Options:        []tcp.TCPOption{},
	}

	conn, err := net.Dial("ip4:tcp", s.targetIP.String())
	if err != nil {
		log.Fatalf("Error dialing host: %s/\n", err)
	}

	for _, port := range s.targetPorts {
		tcpPacket.Destination = port

		data := tcpPacket.Marshal()
		tcpPacket.Checksum = tcp.Csum(data, [4]byte(s.sourceIP.IP), [4]byte(s.targetIP.IP))
		data = tcpPacket.Marshal()

		_, err := conn.Write(data)
		if err != nil {
			fmt.Printf("Error sending packet to port: %d\n", port)
		}

		//fmt.Println("Found open port:", port)
	}

	conn, err = net.ListenIP("ip4:tcp", s.sourceIP)

	conn.Close()
}

func handleArgs(args []string) (*Scanner, string, error) {
	scanner := new(Scanner)

	if len(args) == 1 {
		return scanner, "", fmt.Errorf("Usage: scango <target-ip> port1,port1,port3")
	}

	// TODO: validate targetIP argument
	sourceIP, err := net.ResolveIPAddr("ip4", args[1])
	if err != nil {
		log.Fatalf("net.ResolveIPAddr: %s. %s\n", args[1], sourceIP)
	}
	scanner.sourceIP = sourceIP

	targetIP, err := net.ResolveIPAddr("ip4", args[2])
	if err != nil {
		log.Fatalf("net.ResolveIPAddr: %s. %s\n", args[2], targetIP)
	}
	scanner.targetIP = targetIP

	// TODO: validate targetPorts argument
	scanner.targetPorts = []uint16{211, 80, 8080}

	// TODO: validate scanType argument
	scanType := "syn"

	return scanner, scanType, nil
}

func main() {
	args := os.Args

	scanner, scanType, err := handleArgs(args)
	if err != nil {
		log.Fatal(err)
	}

	scanner.RunScan(scanType)
}
