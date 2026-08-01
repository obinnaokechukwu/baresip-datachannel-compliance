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
	payload     []byte
	address     net.Addr
	channelData bool
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
	DataDropped     uint64 `json:"dataDropped"`
	DataMTUDropped  uint64 `json:"dataMtuDropped"`
	DataDelayed     uint64 `json:"dataDelayed"`
	DataJittered    uint64 `json:"dataJittered"`
	DataBandwidth   uint64 `json:"dataBandwidthDelayed"`
	DataReordered   uint64 `json:"dataReordered"`
	DataDuplicated  uint64 `json:"dataDuplicated"`
	MinDelayMillis  int64  `json:"minAppliedDelayMillis"`
	MaxDelayMillis  int64  `json:"maxAppliedDelayMillis"`
}

type impairedPacketConn struct {
	net.PacketConn
	statsMutex     sync.Mutex
	ready          []*packet
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

func (conn *impairedPacketConn) wait(
	sequence uint64, size int, channelData bool,
) {
	wait := conn.delay
	jittered := false
	if conn.jitter > 0 {
		steps := int64(conn.jitter/time.Millisecond)*2 + 1
		offset := int64(sequence%uint64(steps)) - steps/2
		wait += time.Duration(offset) * time.Millisecond
		jittered = offset != 0
	}
	bandwidthDelayed := false
	if conn.bandwidth > 0 {
		wait += time.Duration(
			uint64(size) * 8 * uint64(time.Second) / conn.bandwidth,
		)
		bandwidthDelayed = size > 0
	}
	if wait > 0 {
		conn.statsMutex.Lock()
		conn.stats.Delayed++
		if channelData {
			conn.stats.DataDelayed++
			if jittered {
				conn.stats.DataJittered++
			}
			if bandwidthDelayed {
				conn.stats.DataBandwidth++
			}
		}
		millis := wait.Milliseconds()
		if conn.stats.MinDelayMillis == 0 || millis < conn.stats.MinDelayMillis {
			conn.stats.MinDelayMillis = millis
		}
		if millis > conn.stats.MaxDelayMillis {
			conn.stats.MaxDelayMillis = millis
		}
		conn.statsMutex.Unlock()
		time.Sleep(wait)
	}
}

func isChannelData(buffer []byte, n int) bool {
	return n >= 4 && buffer[0]&0xc0 == 0x40
}

func copyPacket(buffer []byte, n int, address net.Addr) *packet {
	payload := make([]byte, n)
	copy(payload, buffer[:n])
	return &packet{
		payload: payload, address: address,
		channelData: isChannelData(buffer, n),
	}
}

func returnPacket(buffer []byte, value *packet) (int, net.Addr, error) {
	return copy(buffer, value.payload), value.address, nil
}

func (conn *impairedPacketConn) nextPacket(
	buffer []byte,
) (*packet, uint64, error) {
	for {
		n, address, err := conn.readPacket(buffer)
		if err != nil {
			return nil, 0, err
		}
		conn.sequence++
		sequence := conn.sequence
		channelData := isChannelData(buffer, n)
		if conn.mtu > 0 && n > conn.mtu {
			conn.statsMutex.Lock()
			conn.stats.MTUDropped++
			if channelData {
				conn.stats.DataMTUDropped++
			}
			conn.statsMutex.Unlock()
			continue
		}
		if conn.dropEvery > 0 && sequence%conn.dropEvery == 0 {
			conn.statsMutex.Lock()
			conn.stats.Dropped++
			if channelData {
				conn.stats.DataDropped++
			}
			conn.statsMutex.Unlock()
			continue
		}
		conn.wait(sequence, n, channelData)
		return copyPacket(buffer, n, address), sequence, nil
	}
}

func (conn *impairedPacketConn) ReadFrom(
	buffer []byte,
) (int, net.Addr, error) {
	if len(conn.ready) > 0 {
		value := conn.ready[0]
		conn.ready = conn.ready[1:]
		return returnPacket(buffer, value)
	}
	current, sequence, err := conn.nextPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	duplicateCurrent := conn.duplicateEvery > 0 &&
		sequence%conn.duplicateEvery == 0
	if duplicateCurrent {
		conn.statsMutex.Lock()
		conn.stats.Duplicated++
		if current.channelData {
			conn.stats.DataDuplicated++
		}
		conn.statsMutex.Unlock()
	}
	if conn.reorderEvery > 0 && sequence%conn.reorderEvery == 0 {
		nextBuffer := make([]byte, len(buffer))
		next, nextSequence, nextErr := conn.nextPacket(nextBuffer)
		if nextErr != nil {
			return 0, nil, nextErr
		}
		duplicateNext := conn.duplicateEvery > 0 &&
			nextSequence%conn.duplicateEvery == 0
		conn.statsMutex.Lock()
		conn.stats.Reordered++
		if current.channelData || next.channelData {
			conn.stats.DataReordered++
		}
		if duplicateNext {
			conn.stats.Duplicated++
			if next.channelData {
				conn.stats.DataDuplicated++
			}
		}
		conn.statsMutex.Unlock()
		if duplicateNext {
			conn.ready = append(conn.ready, next)
		}
		conn.ready = append(conn.ready, current)
		if duplicateCurrent {
			conn.ready = append(conn.ready, current)
		}
		return returnPacket(buffer, next)
	}
	if duplicateCurrent {
		conn.ready = append(conn.ready, current)
	}
	return returnPacket(buffer, current)
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
