package netlink

import (
	"bytes"
	"encoding/binary"
	"net"
	"syscall"
	"testing"
)

func TestMapTCPState(t *testing.T) {
	tests := []struct {
		state uint8
		want  string
	}{
		{tcpEstablished, "ESTABLISHED"},
		{tcpSynSent, "SYN_SENT"},
		{tcpSynRecv, "SYN_RECV"},
		{tcpFinWait1, "FIN_WAIT1"},
		{tcpFinWait2, "FIN_WAIT2"},
		{tcpTimeWait, "TIME_WAIT"},
		{tcpClose, "CLOSE"},
		{tcpCloseWait, "CLOSE_WAIT"},
		{tcpLastAck, "LAST_ACK"},
		{tcpListen, "LISTEN"},
		{tcpClosing, "CLOSING"},
		{99, "UNKNOWN"},
	}

	for _, tt := range tests {
		got := mapTCPState(tt.state)
		if got != tt.want {
			t.Errorf("mapTCPState(%d) = %q; want %q", tt.state, got, tt.want)
		}
	}
}

func TestParseNetlinkBuffer_IPv4AndIPv6(t *testing.T) {
	// 1. IPv4 test
	var diagMsg inetDiagMsg
	diagMsg.Family = syscall.AF_INET
	diagMsg.State = tcpEstablished
	diagMsg.Inode = 9999
	diagMsg.UID = 1000
	diagMsg.Id.Src = [16]byte{192, 168, 1, 100}
	diagMsg.Id.Dst = [16]byte{1, 1, 1, 1}
	diagMsg.Id.Sport = binary.LittleEndian.Uint16([]byte{0xD4, 0x31})
	diagMsg.Id.Dport = binary.LittleEndian.Uint16([]byte{0x01, 0xBB})

	tcpInfoData := make([]byte, 180)
	binary.LittleEndian.PutUint32(tcpInfoData[32:36], 15000)
	binary.LittleEndian.PutUint64(tcpInfoData[160:168], 50000)
	binary.LittleEndian.PutUint64(tcpInfoData[168:176], 120000)

	var rta rtattr
	rta.Len = uint16(4 + len(tcpInfoData))
	rta.Type = inetDiagInfo

	msgBuf := new(bytes.Buffer)
	binary.Write(msgBuf, binary.LittleEndian, diagMsg)
	binary.Write(msgBuf, binary.LittleEndian, rta)
	msgBuf.Write(tcpInfoData)

	nlh := nlmsghdr{
		Len:   uint32(16 + msgBuf.Len()),
		Type:  sockDiagByFamily,
		Flags: nlmFMulti,
		Seq:   1,
		Pid:   0,
	}

	totalBuf := new(bytes.Buffer)
	binary.Write(totalBuf, binary.LittleEndian, nlh)
	totalBuf.Write(msgBuf.Bytes())

	// Add NLMSG_DONE
	doneH := nlmsghdr{
		Len:  16,
		Type: 3, // NLMSG_DONE
	}
	binary.Write(totalBuf, binary.LittleEndian, doneH)

	done, conns, err := parseNetlinkBuffer(totalBuf.Bytes(), syscall.AF_INET, false)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if !done {
		t.Errorf("expected done=true")
	}
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}

	c := conns[0]
	if c.RemoteIP.String() != "1.1.1.1" {
		t.Errorf("expected remote 1.1.1.1, got %s", c.RemoteIP)
	}
	if c.Inode != 9999 {
		t.Errorf("expected inode 9999, got %d", c.Inode)
	}
	if c.TXBytes != 50000 {
		t.Errorf("expected TXBytes 50000, got %d", c.TXBytes)
	}
	if c.RXBytes != 120000 {
		t.Errorf("expected RXBytes 120000, got %d", c.RXBytes)
	}
	if c.RTT.Microseconds() != 15000 {
		t.Errorf("expected RTT 15000us, got %v", c.RTT)
	}

	// 2. IPv6 test
	var diagMsg6 inetDiagMsg
	diagMsg6.Family = syscall.AF_INET6
	diagMsg6.State = tcpEstablished
	diagMsg6.Inode = 8888
	copy(diagMsg6.Id.Src[:], net.ParseIP("2001:db8::1"))
	copy(diagMsg6.Id.Dst[:], net.ParseIP("2001:db8::2"))

	msgBuf6 := new(bytes.Buffer)
	binary.Write(msgBuf6, binary.LittleEndian, diagMsg6)

	nlh6 := nlmsghdr{
		Len:   uint32(16 + msgBuf6.Len()),
		Type:  sockDiagByFamily,
		Flags: nlmFMulti,
	}

	totalBuf6 := new(bytes.Buffer)
	binary.Write(totalBuf6, binary.LittleEndian, nlh6)
	totalBuf6.Write(msgBuf6.Bytes())
	binary.Write(totalBuf6, binary.LittleEndian, doneH)

	done6, conns6, err := parseNetlinkBuffer(totalBuf6.Bytes(), syscall.AF_INET6, false)
	if err != nil {
		t.Fatalf("unexpected ipv6 parse error: %v", err)
	}
	if !done6 || len(conns6) != 1 {
		t.Fatalf("expected 1 ipv6 connection, got %d", len(conns6))
	}
	if conns6[0].RemoteIP.String() != "2001:db8::2" {
		t.Errorf("expected remote IPv6 2001:db8::2, got %s", conns6[0].RemoteIP)
	}
}

func TestNewScanner(t *testing.T) {
	scanner := NewScanner()
	if scanner == nil {
		t.Fatalf("expected non-nil scanner")
	}
	// ScanSockets live test on this linux system
	conns, err := scanner.ScanSockets(true)
	if err != nil {
		t.Logf("ScanSockets returned error (expected if permissions restricted): %v", err)
	} else {
		t.Logf("ScanSockets returned %d connections", len(conns))
	}
}
