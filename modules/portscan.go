package modules

import (
	"gwall-slave/log"
	"gwall-slave/packets"
	"net"
)

type PortscanModule struct {
	PacketCh       chan []packets.PackData
	PortsTreshhold int
	ipBufferSize   int
	myIp           net.IP
	logger         *log.Logger
}

func AnalyzePortScan(pm *PortscanModule, packets []packets.PackData) {
	if len(packets) == 0 {
		return
	}

	data := make(map[string][]string)
	for _, packet := range packets {
		if packet.SrcIp.String() != pm.myIp.String() {
			if !stringInSlice(packet.DstPort.String(), data[packet.SrcIp.String()]) {
				data[packet.SrcIp.String()] = append(data[packet.SrcIp.String()], packet.DstPort.String())
			}
		}
	}

	//fmt.Println("END DATA ", data)
	for ip, portData := range data {
		if len(portData) > pm.PortsTreshhold {
			pm.logger.Log("[Warning] Possible port scan from: ", ip)
		}
	}
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
		ipBufferSize:   100,
		PacketCh:       make(chan []packets.PackData),
		PortsTreshhold: 30,
		logger:         logger,
	}
}
