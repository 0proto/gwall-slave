package modules

import (
	"gwall-slave/packets"
	"net"
)

type Module interface {
	OnAdded(myIP net.IP) error
	OnRemoved() error
	onProcess()

	OnSnifferData(pData []packets.PackData)
}
