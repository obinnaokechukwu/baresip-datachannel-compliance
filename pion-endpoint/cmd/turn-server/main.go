package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/pion/turn/v5"
)

type packet struct {
	payload []byte
	address net.Addr
}

type impairmentStats struct {
	ReadPackets     uint64 `json:"readPackets"`
	ReadBytes       uint64 `json:"readBytes"`
	Dropped         uint64 `json:"dropped"`
	MTUDropped      uint64 `json:"mtuDropped"`
	Delayed         uint64 `json:"delayed"`
	Reordered       uint64 `json:"reordered"`
	Duplicated      uint64 `json:"duplicated"`
	MaxDatagramSize int    `json:"maxDatagramSize"`
	DelayMillis     int64  `json:"delayMillis"`
	JitterMillis    int64  `json:"jitterMillis"`
	Bandwidth       uint64 `json:"bandwidthBitsPerSecond"`
	MTU             int    `json:"mtu"`
}

type impairedPacketConn struct {
	net.PacketConn
	statsMutex     sync.Mutex
	pending        *packet
	duplicate      *packet
	sequence       uint64
	dropEvery      uint64
	reorderEvery   uint64
	duplicateEvery uint64
	delay          time.Duration
	jitter         time.Duration
	bandwidth      uint64
	mtu            int
	stats          impairmentStats
}

func (conn *impairedPacketConn) readPacket(
	buffer []byte,
) (int, net.Addr, error) {
	n, address, err := conn.PacketConn.ReadFrom(buffer)
	if err != nil {
		return n, address, err
	}
	conn.statsMutex.Lock()
	conn.stats.ReadPackets++
	conn.stats.ReadBytes += uint64(n)
	if n > conn.stats.MaxDatagramSize {
		conn.stats.MaxDatagramSize = n
	}
	conn.statsMutex.Unlock()
	return n, address, nil
}

func (conn *impairedPacketConn) wait(sequence uint64, size int) {
	wait := conn.delay
	if conn.jitter > 0 {
		steps := int64(conn.jitter/time.Millisecond)*2 + 1
		offset := int64(sequence%uint64(steps)) - steps/2
		wait += time.Duration(offset) * time.Millisecond
	}
	if conn.bandwidth > 0 {
		wait += time.Duration(
			uint64(size) * 8 * uint64(time.Second) / conn.bandwidth,
		)
	}
	if wait > 0 {
		conn.statsMutex.Lock()
		conn.stats.Delayed++
		conn.statsMutex.Unlock()
		time.Sleep(wait)
	}
}

func copyPacket(buffer []byte, n int, address net.Addr) *packet {
	payload := make([]byte, n)
	copy(payload, buffer[:n])
	return &packet{payload: payload, address: address}
}

func returnPacket(buffer []byte, value *packet) (int, net.Addr, error) {
	return copy(buffer, value.payload), value.address, nil
}

func (conn *impairedPacketConn) ReadFrom(
	buffer []byte,
) (int, net.Addr, error) {
	if conn.duplicate != nil {
		value := conn.duplicate
		conn.duplicate = nil
		return returnPacket(buffer, value)
	}
	if conn.pending != nil {
		value := conn.pending
		conn.pending = nil
		return returnPacket(buffer, value)
	}

	for {
		n, address, err := conn.readPacket(buffer)
		if err != nil {
			return n, address, err
		}
		conn.sequence++
		sequence := conn.sequence
		if conn.mtu > 0 && n > conn.mtu {
			conn.statsMutex.Lock()
			conn.stats.MTUDropped++
			conn.statsMutex.Unlock()
			continue
		}
		if conn.dropEvery > 0 && sequence%conn.dropEvery == 0 {
			conn.statsMutex.Lock()
			conn.stats.Dropped++
			conn.statsMutex.Unlock()
			continue
		}
		conn.wait(sequence, n)
		current := copyPacket(buffer, n, address)
		if conn.duplicateEvery > 0 &&
			sequence%conn.duplicateEvery == 0 {
			conn.statsMutex.Lock()
			conn.stats.Duplicated++
			conn.statsMutex.Unlock()
			conn.duplicate = current
		}
		if conn.reorderEvery > 0 &&
			sequence%conn.reorderEvery == 0 {
			nextBuffer := make([]byte, len(buffer))
			nextN, nextAddress, nextErr := conn.readPacket(nextBuffer)
			if nextErr != nil {
				return nextN, nextAddress, nextErr
			}
			conn.statsMutex.Lock()
			conn.stats.Reordered++
			conn.statsMutex.Unlock()
			conn.pending = current
			conn.wait(sequence+1, nextN)
			return nextN, nextAddress, nil
		}
		return returnPacket(buffer, current)
	}
}

func (conn *impairedPacketConn) snapshot() impairmentStats {
	conn.statsMutex.Lock()
	defer conn.statsMutex.Unlock()
	result := conn.stats
	result.DelayMillis = conn.delay.Milliseconds()
	result.JitterMillis = conn.jitter.Milliseconds()
	result.Bandwidth = conn.bandwidth
	result.MTU = conn.mtu
	return result
}

func main() {
	publicIP := flag.String("public-ip", "", "advertised relay IPv4 address")
	port := flag.Int("port", 0, "TURN UDP listen port")
	username := flag.String("username", "baresip", "TURN username")
	password := flag.String("password", "acceptance", "TURN password")
	realm := flag.String("realm", "baresip.test", "TURN realm")
	dropEvery := flag.Uint64("drop-every", 0, "drop every Nth inbound packet")
	reorderEvery := flag.Uint64(
		"reorder-every", 0, "reorder every Nth inbound packet",
	)
	duplicateEvery := flag.Uint64(
		"duplicate-every", 0, "duplicate every Nth inbound packet",
	)
	delay := flag.Duration("delay", 0, "fixed inbound packet delay")
	jitter := flag.Duration("jitter", 0, "deterministic delay variation")
	bandwidth := flag.Uint64("bandwidth", 0, "inbound bit/s limit")
	mtu := flag.Int("mtu", 0, "drop inbound datagrams larger than this")
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

	impaired := &impairedPacketConn{
		PacketConn:     listener,
		dropEvery:      *dropEvery,
		reorderEvery:   *reorderEvery,
		duplicateEvery: *duplicateEvery,
		delay:          *delay,
		jitter:         *jitter,
		bandwidth:      *bandwidth,
		mtu:            *mtu,
	}
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
			PacketConn: impaired,
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
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
	for received := range signals {
		if received == syscall.SIGUSR1 {
			_ = json.NewEncoder(os.Stdout).Encode(impaired.snapshot())
			continue
		}
		break
	}
}
