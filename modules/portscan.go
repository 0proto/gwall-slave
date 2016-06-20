package modules

import (
	"net"

	"github.com/0prototype/gwall-master/entities"
	"github.com/0prototype/gwall-slave/log"
	"github.com/0prototype/gwall-slave/packets"
)

type PortscanModule struct {
	PacketCh       chan []packets.PackData
	PortsTreshhold int
	pData          map[string][]string
	myIp           net.IP
	logger         *log.Logger
}

func AnalyzePortScan(pm *PortscanModule,
	packets []packets.PackData) {
	if len(packets) == 0 {
		return
	}
	for _, packet := range packets {
		if packet.SrcIp.String() != pm.myIp.String() &&
			packet.Syn {
			if !stringInSlice(packet.DstPort.String(),
				pm.pData[packet.SrcIp.String()]) {
				pm.pData[packet.SrcIp.String()] =
					append(pm.pData[packet.SrcIp.String()],
						packet.DstPort.String())
			}
		}
	}
	for ip, portData := range pm.pData {
		if len(portData) > pm.PortsTreshhold {
			SendAlert(&entities.Alert{
				AlertType: entities.PortScanAlert,
				Title:     "Detected possible port scan attempt",
				Message:   "IP address of scanning host: " + ip,
			})
		}
	}
	pm.pData = make(map[string][]string)
}

func stringInSlice(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}

func (pm *PortscanModule) OnAdded(myIP net.IP) error {
	go pm.onProcess()
	pm.myIp = myIP
	return nil
}

func (pm *PortscanModule) onProcess() {
	for {
		select {
		case newPackets := <-pm.PacketCh:
			AnalyzePortScan(pm, newPackets)
		}
	}
}

func (pm *PortscanModule) OnRemoved() error {
	return nil
}

func (pm *PortscanModule) OnSnifferData(pData []packets.PackData) {
	pm.PacketCh <- pData
}

func NewPortscanModule(logger *log.Logger) *PortscanModule {
	return &PortscanModule{
		PacketCh: make(chan []packets.PackData),

		PortsTreshhold: 30,
		logger:         logger,
	}
}
