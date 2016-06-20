package modules

import (
	"net"
	"strconv"

	"github.com/0prototype/gwall-master/entities"
	"github.com/0prototype/gwall-slave/log"
	"github.com/0prototype/gwall-slave/packets"
)

type AnomalyModule struct {
	PacketCh chan []packets.PackData
	alpha    float64
	beta     float64
	k        int
	un       float64
	un1      float64
	xn       int
	alarms   int
	timesM   int
	pData    map[string][]string
	myIp     net.IP
	logger   *log.Logger
}

func AdaptiveThreshold(am *AnomalyModule, packets []packets.PackData) {
	if len(packets) == 0 {
		return
	}
	am.xn = 0
	for _, packet := range packets {
		if packet.Syn && !packet.Ack && packet.SrcIp.String() != am.myIp.String() {
			am.xn++
		}
	}
	am.un = am.beta*am.un1 + (1-am.beta)*float64(am.xn)
	if float64(am.xn) > (am.alpha+1)*am.un1 {
		am.alarms++
	}
	if am.alarms > am.k {
		SendAlert(&entities.Alert{
			AlertType: entities.AnomalyAlert,
			Title:     "Detected possible syn flooding attempt",
			Message:   "Current incoming syn packets count: " + strconv.Itoa(int(am.xn)),
		})
	}
	if am.timesM > am.k {
		am.timesM = 0
	}
	am.timesM++
	am.un1 = am.un
}

func (am *AnomalyModule) OnAdded(myIP net.IP) error {
	go am.onProcess()
	am.myIp = myIP
	return nil
}

func (am *AnomalyModule) onProcess() {
	for {
		select {
		case newPackets := <-am.PacketCh:
			AdaptiveThreshold(am, newPackets)
		}
	}
}

func (am *AnomalyModule) OnRemoved() error {
	return nil
}

func (am *AnomalyModule) OnSnifferData(pData []packets.PackData) {
	am.PacketCh <- pData
}

func NewAnomalyModule(logger *log.Logger) *AnomalyModule {
	return &AnomalyModule{
		PacketCh: make(chan []packets.PackData),
		alpha:    0.5,
		beta:     0.98,
		k:        5,
		un:       1,
		un1:      0,
		xn:       0,
		logger:   logger,
	}
}
