package log

import (
	"log"
	"os"
)

type Logger struct {
	LogPath string
}

func NewLogger(logPath string) *Logger {
	return &Logger{
		LogPath: logPath,
	}
}

func (l *Logger) Log(msgs ...interface{}) {
	f, err := os.OpenFile(l.LogPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)
	log.Println(msgs...)
	log.SetOutput(os.Stdout)
	log.Println(msgs...)
}

func (l *Logger) Fatal(msgs ...interface{}) {
	f, err := os.OpenFile(l.LogPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)
	log.Fatalln(msgs...)
	log.SetOutput(os.Stdout)
	log.Fatalln(msgs...)
}
