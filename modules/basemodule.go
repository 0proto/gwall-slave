package modules

import (
	"net"

	"github.com/0prototype/gwall-master/entities"
	"github.com/0prototype/gwall-slave/packets"
)

type Module interface {
	OnAdded(myIP net.IP) error
	OnRemoved() error
	onProcess()

	OnSnifferData(pData []packets.PackData)
}

func GenerateAlert(alertType int, priority int, title string, message string) *entities.Alert {
	return &entities.Alert{
		AlertType: alertType,
		Priority:  priority,
		Title:     title,
		Message:   message,
	}
}

func SendAlert(a *entities.Alert) {
}
