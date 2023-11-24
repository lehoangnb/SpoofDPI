package proxy

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/lehoangnb/SpoofDPI/net"
	"github.com/lehoangnb/SpoofDPI/packet"
	"github.com/lehoangnb/SpoofDPI/util"
)

type Proxy struct {
	addr    string
	port    int
	timeout int
}

func New(config *util.Config) *Proxy {
	return &Proxy{
		addr:    *config.Addr,
		port:    *config.Port,
		timeout: *config.Timeout,
	}
}

func (p *Proxy) TcpAddr() *net.TCPAddr {
	return net.TcpAddr(p.addr, p.port)
}

func (p *Proxy) Port() int {
	return p.port
}

func (p *Proxy) Start() {
	l, err := net.ListenTCP("tcp4", p.TcpAddr())
	if err != nil {
		log.Fatal("Error creating listener: ", err)
		os.Exit(1)
	}

	if p.timeout > 0 {
        log.Println(fmt.Sprintf("Connection timeout is set to %dms", p.timeout))
    }

    log.Println("Created a listener on port", p.Port())

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("Error accepting connection: ", err)
			continue
		}

		go func() {
			b, err := conn.ReadBytes()
			if err != nil {
				return
			}

			log.Debug("[PROXY] Request from ", conn.RemoteAddr(), "\n\n", string(b))

			pkt, err := packet.NewHttpPacket(b)
			if err != nil {
				log.Debug("Error while parsing request: ", string(b))
				return
			}

			if !pkt.IsValidMethod() {
				log.Debug("Unsupported method: ", pkt.Method())
				return
			}

			if pkt.IsConnectMethod() {
				log.Debug("[HTTPS] Start")
				conn.HandleHttps(pkt, p.timeout)
			} else {
				log.Debug("[HTTP] Start")
				conn.HandleHttp(pkt, p.timeout)
			}
		}()
	}
}
