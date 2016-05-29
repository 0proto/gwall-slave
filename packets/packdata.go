package packets

import (
	"fmt"
	"net"

	"github.com/google/gopacket/layers"
)

type PackData struct {
	timestamp int64
	SrcIp     net.IP
	DstIp     net.IP
	SrcPort   layers.TCPPort
	DstPort   layers.TCPPort
	Syn       bool
	Ack       bool
	Size      int
}

func (p *PackData) String() string {
	return fmt.Sprintf("%s:%s -> %s:%s | %d bytes.", p.SrcIp, p.SrcPort, p.DstIp, p.DstPort, p.Size)
}
