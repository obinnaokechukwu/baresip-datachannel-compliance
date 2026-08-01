package main

import (
	"errors"
	"net"
	"testing"
	"time"
)

type queuedDatagram struct {
	payload []byte
}

type fakePacketConn struct {
	packets []queuedDatagram
}

func (conn *fakePacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	if len(conn.packets) == 0 {
		return 0, nil, errors.New("empty packet queue")
	}
	value := conn.packets[0]
	conn.packets = conn.packets[1:]
	return copy(buffer, value.payload), &net.UDPAddr{}, nil
}

func (*fakePacketConn) WriteTo([]byte, net.Addr) (int, error) { return 0, nil }
func (*fakePacketConn) Close() error                          { return nil }
func (*fakePacketConn) LocalAddr() net.Addr                   { return &net.UDPAddr{} }
func (*fakePacketConn) SetDeadline(time.Time) error           { return nil }
func (*fakePacketConn) SetReadDeadline(time.Time) error       { return nil }
func (*fakePacketConn) SetWriteDeadline(time.Time) error      { return nil }

func channelPacket(size int, fill byte) []byte {
	value := make([]byte, size)
	value[0] = 0x40
	value[1] = 0x01
	for index := 4; index < len(value); index++ {
		value[index] = fill
	}
	return value
}

func TestReorderLookaheadStillAppliesMTU(t *testing.T) {
	underlying := &fakePacketConn{packets: []queuedDatagram{
		{payload: channelPacket(20, 1)},
		{payload: channelPacket(101, 2)},
		{payload: channelPacket(30, 3)},
	}}
	conn := &impairedPacketConn{
		PacketConn:   underlying,
		reorderEvery: 1,
		mtu:          100,
	}
	buffer := make([]byte, 200)

	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n != 30 || buffer[4] != 3 {
		t.Fatalf("lookahead packet = %d/%d, want 30/3", n, buffer[4])
	}
	stats := conn.snapshot()
	if stats.MTUDropped != 1 || stats.DataMTUDropped != 1 {
		t.Fatalf("MTU counters = %+v", stats)
	}
	if stats.Reordered != 1 || stats.DataReordered != 1 {
		t.Fatalf("reorder counters = %+v", stats)
	}

	n, _, err = conn.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n != 20 || buffer[4] != 1 {
		t.Fatalf("pending packet = %d/%d, want 20/1", n, buffer[4])
	}
}

func TestDataDelayMetricsProveJitterAndBandwidth(t *testing.T) {
	conn := &impairedPacketConn{
		delay:     1 * time.Millisecond,
		jitter:    1 * time.Millisecond,
		bandwidth: 8_000_000,
	}
	for sequence := uint64(1); sequence <= 3; sequence++ {
		conn.wait(sequence, 1000, true)
	}
	stats := conn.snapshot()
	if stats.DataDelayed != 3 || stats.DataJittered == 0 ||
		stats.DataBandwidth != 3 {
		t.Fatalf("data delay counters = %+v", stats)
	}
	if stats.MinDelayMillis >= stats.MaxDelayMillis {
		t.Fatalf("delay variation missing: %+v", stats)
	}
}
