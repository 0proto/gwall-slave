package sniffer

import (
	"net"
	"time"

	"github.com/0prototype/gwall-slave/log"
	"github.com/0prototype/gwall-slave/modules"
	"github.com/0prototype/gwall-slave/packets"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type SnifferConfig struct {
	Device      string
	Filter      string
	SnapshotLen int32
	Promiscous  bool
	Period      int64
	Timeout     time.Duration
	Handle      *pcap.Handle
	Modules     []modules.Module
	MyLocalIP   net.IP
}

type Sniffer struct {
	cfg               SnifferConfig
	logger            *log.Logger
	startTime         time.Time
	packDataHistory   map[int64][]packets.PackData
	packDataHistoryCh chan []packets.PackData
	currentQueue      []packets.PackData
	queueTime         time.Time
	packDataCh        chan packets.PackData
}

func (s *Sniffer) Start() {
	s.startTime = time.Now()
	s.logger.Log("Sniffer started on ", s.startTime)
	s.logger.Log("Active modules: ", len(s.cfg.Modules))
	go s.initPacketSource()
	go s.updateQueue()
}

func (s *Sniffer) InitModules() {
	for _, mod := range s.cfg.Modules {
		mod.OnAdded(s.cfg.MyLocalIP)
	}
}

func (s *Sniffer) Update() {
	for {
		select {
		case pHistory := <-s.packDataHistoryCh:
			s.packDataHistory[time.Now().Unix()] = pHistory
		case packet := <-s.packDataCh:
			s.currentQueue = append(s.currentQueue, packet)
		}
	}
}

func (s *Sniffer) updateQueue() {
	currentTime := time.Now().Unix()
	for {
		if currentTime < time.Now().Unix()-s.cfg.Period {
			currentTime = time.Now().Unix()
			for _, mod := range s.cfg.Modules {
				mod.OnSnifferData(s.currentQueue[:])
			}
			s.AddHistory(s.currentQueue[:])
			s.currentQueue = []packets.PackData{}
		}
	}
}

func (s *Sniffer) initPacketSource() {
	var err error

	s.cfg.Handle, err = pcap.OpenLive(s.cfg.Device, s.cfg.SnapshotLen, s.cfg.Promiscous, s.cfg.Timeout)
	if err != nil {
		s.logger.Fatal(err)
	}
	err = s.cfg.Handle.SetBPFFilter(s.cfg.Filter)
	if err != nil {
		panic(err)
	}
	defer s.cfg.Handle.Close()

	packetSource := gopacket.NewPacketSource(s.cfg.Handle, s.cfg.Handle.LinkType())
	var pData packets.PackData
	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			pData.SrcPort = tcp.SrcPort
			pData.DstPort = tcp.DstPort
			pData.Size = len(tcp.Contents)
			pData.Syn = tcp.SYN
			pData.Ack = tcp.ACK
		}

		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			pData.SrcIp = ip.SrcIP
			pData.DstIp = ip.DstIP
		}
		s.AddPacket(pData)
	}
}

func (s *Sniffer) AddPacket(pData packets.PackData) {
	s.packDataCh <- pData
}

func (s *Sniffer) AddHistory(pHistory []packets.PackData) {
	s.packDataHistoryCh <- pHistory
}

func NewSniffer(config SnifferConfig, logger *log.Logger) *Sniffer {
	return &Sniffer{
		cfg:               config,
		packDataHistory:   make(map[int64][]packets.PackData),
		packDataHistoryCh: make(chan []packets.PackData),
		packDataCh:        make(chan packets.PackData),
		currentQueue:      make([]packets.PackData, 1),
		logger:            logger,
	}
}
