package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/lehoangnb/SpoofDPI/doh"
	"github.com/lehoangnb/SpoofDPI/proxy"
	"github.com/lehoangnb/SpoofDPI/util"
)

func main() {
	util.ParseArgs()
    config := util.GetConfig()

	p := proxy.New(config)
	doh.Init(*config.Dns, *config.Nodoh)
	if *config.Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	if *config.NoBanner {
		util.PrintSimpleInfo()
	} else {
		util.PrintColoredBanner()
	}

	if err := util.SetOsProxy(*config.Port); err != nil {
		log.Fatal(err)
	}

	go p.Start()

	// Handle signals
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(
		sigs,
		syscall.SIGKILL,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGHUP)

	go func() {
		_ = <-sigs
		done <- true
	}()

	<-done
	if err := util.UnsetOsProxy(); err != nil {
		log.Fatal(err)
	}
}
