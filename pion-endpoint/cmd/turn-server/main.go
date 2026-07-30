package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/pion/turn/v5"
)

func main() {
	publicIP := flag.String("public-ip", "", "advertised relay IPv4 address")
	port := flag.Int("port", 0, "TURN UDP listen port")
	username := flag.String("username", "baresip", "TURN username")
	password := flag.String("password", "acceptance", "TURN password")
	realm := flag.String("realm", "baresip.test", "TURN realm")
	flag.Parse()
	if net.ParseIP(*publicIP) == nil {
		fmt.Fprintln(os.Stderr, "invalid public IP")
		os.Exit(2)
	}

	listener, err := net.ListenPacket(
		"udp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(*port)),
	)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	key := turn.GenerateAuthKey(*username, *realm, *password)
	server, err := turn.NewServer(turn.ServerConfig{
		Realm: *realm,
		AuthHandler: func(
			attributes *turn.RequestAttributes,
		) (string, []byte, bool) {
			if attributes.Username != *username {
				return "", nil, false
			}
			return *username, key, true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: listener,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP(*publicIP),
				Address:      "0.0.0.0",
			},
		}},
	})
	if err != nil {
		panic(err)
	}
	defer server.Close()

	address := listener.LocalAddr().(*net.UDPAddr)
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"ready":   true,
		"address": net.JoinHostPort(*publicIP, strconv.Itoa(address.Port)),
	})

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals
}
