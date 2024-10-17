package tcp

import (
	"bytes"
	"encoding/binary"
)

const (
	FIN = 0b000001
	SYN = 0b000010
	RST = 0b000100
	PSH = 0b001000
	ACK = 0b010000
	URG = 0b100000
)

type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

type TCPHeader struct {
	Source         uint16
	Destination    uint16
	Sequence       uint32
	Acknowledgment uint32
	DataOffset     uint8 // 4 bits !!
	Reserved       uint8 // 3 bits !!
	ECN            uint8 // 3 bits !!
	Ctrl           uint8 // 6 bits !!
	Window         uint16
	Checksum       uint16
	Urgent         uint16
	Options        []TCPOption
}

func NewTCPHeader(data []byte) *TCPHeader {
	var tcp TCPHeader

	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &tcp.Source)
	binary.Read(r, binary.BigEndian, &tcp.Destination)
	binary.Read(r, binary.BigEndian, &tcp.Sequence)
	binary.Read(r, binary.BigEndian, &tcp.Acknowledgment)

	var mix uint16
	binary.Read(r, binary.BigEndian, &mix)
	tcp.DataOffset = byte(mix >> 12)
	tcp.Reserved = byte(mix >> 9 & 7)
	tcp.ECN = byte(mix >> 6 & 7)
	tcp.Ctrl = byte(mix & 0x3f)

	binary.Read(r, binary.BigEndian, &tcp.Window)
	binary.Read(r, binary.BigEndian, &tcp.Checksum)
	binary.Read(r, binary.BigEndian, &tcp.Urgent)

	return &tcp
}

func (tcp *TCPHeader) HasFlag(flagBit byte) bool {
	return tcp.Ctrl&flagBit != 0
}

func (tcp *TCPHeader) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, tcp.Source)
	binary.Write(buf, binary.BigEndian, tcp.Destination)
	binary.Write(buf, binary.BigEndian, tcp.Sequence)
	binary.Write(buf, binary.BigEndian, tcp.Acknowledgment)

	var mix uint16
	mix = uint16(tcp.DataOffset)<<12 |
		uint16(tcp.Reserved)<<9 |
		uint16(tcp.ECN)<<6 |
		uint16(tcp.Ctrl)
	binary.Write(buf, binary.BigEndian, mix)

	binary.Write(buf, binary.BigEndian, tcp.Window)
	binary.Write(buf, binary.BigEndian, tcp.Checksum)
	binary.Write(buf, binary.BigEndian, tcp.Urgent)

	for _, option := range tcp.Options {
		binary.Write(buf, binary.BigEndian, option.Kind)
		if option.Length > 1 {
			binary.Write(buf, binary.BigEndian, option.Length)
			binary.Write(buf, binary.BigEndian, option.Data)
		}
	}

	out := buf.Bytes()

	pad := 20 - len(out)
	for i := 0; i < pad; i++ {
		out = append(out, 0)
	}

	return out
}

func Csum(data []byte, sourceIP, destIP [4]byte) uint16 {
	pseudoHeader := []byte{
		sourceIP[0], sourceIP[1], sourceIP[2], sourceIP[3],
		destIP[0], destIP[1], destIP[2], destIP[3],
		0,
		6,
		0, byte(len(data)),
	}

	sumThis := make([]byte, 0, len(pseudoHeader)+len(data))
	sumThis = append(sumThis, pseudoHeader...)
	sumThis = append(sumThis, data...)

	lenSumThis := len(sumThis)
	var nextWord uint16
	var sum uint32
	for i := 0; i+1 < lenSumThis; i += 2 {
		nextWord = uint16(sumThis[i])<<8 | uint16(sumThis[i+1])
		sum += uint32(nextWord)
	}
	if lenSumThis%2 != 0 {
		sum += uint32(sumThis[len(sumThis)-1])
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	return uint16(^sum)
}
