package main

import (
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/0prototype/gwall-slave/log"
	"github.com/0prototype/gwall-slave/modules"
	"github.com/0prototype/gwall-slave/sniffer"

	"github.com/google/gopacket/pcap"
)

var (
	device       string = "en0"
	filter       string = "tcp"
	snapshot_len int32  = 256
	promiscuous  bool   = true
	err          error
	period       int64 = 1
	handle       *pcap.Handle
)

type masterHandler struct {
	mux map[string]func(http.ResponseWriter, *http.Request)
}

func (m *masterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h, ok := m.mux[r.URL.String()]; ok {
		h(w, r)
		return
	}

	io.WriteString(w, "My server: "+r.URL.String())
}

func MyLocalIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		fmt.Println("Error: " + err.Error() + "\n")
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP
			}
		}
	}

	return nil
}

func registerMasterServer() {

}

func info(w http.ResponseWriter, r *http.Request) {

	io.WriteString(w, "[Log]")
}

func main() {
	// Initiate Logger
	logger := log.NewLogger("./krotms-slave.log")

	// Select Monitoring/Analytics Modules
	mdls := make([]modules.Module, 2)
	mdls[0] = modules.NewPortscanModule(logger)
	mdls[1] = modules.NewAnomalyModule(logger)

	// Initialize Sniffer & attach modules
	snfr := sniffer.NewSniffer(sniffer.SnifferConfig{
		Device:      device,
		Filter:      filter,
		SnapshotLen: snapshot_len,
		Promiscous:  promiscuous,
		Period:      period,
		Handle:      handle,
		Modules:     mdls,
		MyLocalIP:   MyLocalIP(),
	}, logger)
	snfr.Start()
	snfr.InitModules()
	snfr.Update()

	mux := make(map[string]func(http.ResponseWriter, *http.Request))

	server := http.Server{
		Addr: ":9966",
		Handler: &masterHandler{
			mux: mux,
		},
	}

	mux["/info"] = info

	server.ListenAndServe()
}
