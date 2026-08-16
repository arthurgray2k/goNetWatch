package netlink

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/arthurgray2k/goNetWatch/internal/classifier"
	"github.com/arthurgray2k/goNetWatch/internal/model"
)

const (
	netlinkInetDiag  = 4
	sockDiagByFamily = 20
	tcpDiagGetSock   = 18
	nlmFRequest      = 1
	nlmFMulti        = 2
	nlmFDump         = 0x300

	inetDiagInfo = 2

	// States
	tcpEstablished = 1
	tcpSynSent     = 2
	tcpSynRecv     = 3
	tcpFinWait1    = 4
	tcpFinWait2    = 5
	tcpTimeWait    = 6
	tcpClose       = 7
	tcpCloseWait   = 8
	tcpLastAck     = 9
	tcpListen      = 10
	tcpClosing     = 11
)

type nlmsghdr struct {
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

type inetDiagSockid struct {
	Sport  uint16
	Dport  uint16
	Src    [16]byte
	Dst    [16]byte
	If     uint32
	Cookie [2]uint32
}

type inetDiagReqV2 struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	Pad      uint8
	States   uint32
	Id       inetDiagSockid
}

type inetDiagMsg struct {
	Family  uint8
	State   uint8
	Timer   uint8
	Retrans uint8
	Id      inetDiagSockid
	Expires uint32
	Rqueue  uint32
	Wqueue  uint32
	UID     uint32
	Inode   uint32
}

type rtattr struct {
	Len  uint16
	Type uint16
}

// Scanner queries Linux sock_diag netlink interface.
type Scanner struct{}

// NewScanner creates a new Netlink scanner.
func NewScanner() *Scanner {
	return &Scanner{}
}

// ScanSockets dumps active TCP sockets for IPv4 and IPv6.
func (s *Scanner) ScanSockets(includeListening bool) ([]*model.Connection, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, netlinkInetDiag)
	if err != nil {
		return nil, fmt.Errorf("open netlink socket: %w", err)
	}
	defer syscall.Close(fd)

	var conns []*model.Connection

	// Dump IPv4 TCP
	ipv4Conns, err := s.dumpFamily(fd, syscall.AF_INET, includeListening)
	if err == nil {
		conns = append(conns, ipv4Conns...)
	}

	// Dump IPv6 TCP
	ipv6Conns, err := s.dumpFamily(fd, syscall.AF_INET6, includeListening)
	if err == nil {
		conns = append(conns, ipv6Conns...)
	}

	return conns, nil
}

func (s *Scanner) dumpFamily(fd int, family uint8, includeListening bool) ([]*model.Connection, error) {
	req := inetDiagReqV2{
		Family:   family,
		Protocol: syscall.IPPROTO_TCP,
		Ext:      (1 << (inetDiagInfo - 1)),
		States:   0xffffffff,
	}

	nlh := nlmsghdr{
		Len:   uint32(16 + binary.Size(req)),
		Type:  sockDiagByFamily,
		Flags: nlmFRequest | nlmFDump,
		Seq:   1,
		Pid:   0,
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, nlh)
	binary.Write(buf, binary.LittleEndian, req)

	err := syscall.Sendto(fd, buf.Bytes(), 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
	if err != nil {
		return nil, err
	}

	var conns []*model.Connection
	recvBuf := make([]byte, 65536)

	for {
		n, _, err := syscall.Recvfrom(fd, recvBuf, 0)
		if err != nil {
			return conns, err
		}

		done, parsed, err := parseNetlinkBuffer(recvBuf[:n], family, includeListening)
		if err != nil {
			return conns, err
		}
		conns = append(conns, parsed...)
		if done {
			break
		}
	}

	return conns, nil
}

func parseNetlinkBuffer(data []byte, family uint8, includeListening bool) (bool, []*model.Connection, error) {
	var conns []*model.Connection
	offset := 0

	for offset+16 <= len(data) {
		var h nlmsghdr
		r := bytes.NewReader(data[offset : offset+16])
		binary.Read(r, binary.LittleEndian, &h)

		if h.Len < 16 || offset+int(h.Len) > len(data) {
			break
		}

		if h.Type == 3 { // NLMSG_DONE
			return true, conns, nil
		}
		if h.Type == 2 { // NLMSG_ERROR
			return true, conns, fmt.Errorf("netlink error message received")
		}

		msgBytes := data[offset+16 : offset+int(h.Len)]
		diagMsgSize := binary.Size(inetDiagMsg{})
		if len(msgBytes) >= diagMsgSize {
			var diagMsg inetDiagMsg
			binary.Read(bytes.NewReader(msgBytes[:diagMsgSize]), binary.LittleEndian, &diagMsg)

			stateStr := mapTCPState(diagMsg.State)
			if includeListening || diagMsg.State != tcpListen {
				localPort := int(binary.BigEndian.Uint16([]byte{byte(diagMsg.Id.Sport), byte(diagMsg.Id.Sport >> 8)}))
				remotePort := int(binary.BigEndian.Uint16([]byte{byte(diagMsg.Id.Dport), byte(diagMsg.Id.Dport >> 8)}))

				var localIP, remoteIP net.IP
				if family == syscall.AF_INET {
					localIP = net.IP(diagMsg.Id.Src[:4])
					remoteIP = net.IP(diagMsg.Id.Dst[:4])
				} else {
					localIP = make(net.IP, 16)
					remoteIP = make(net.IP, 16)
					copy(localIP, diagMsg.Id.Src[:])
					copy(remoteIP, diagMsg.Id.Dst[:])
					if ip4 := remoteIP.To4(); ip4 != nil && isIPv4Mapped(remoteIP) {
						remoteIP = ip4
					}
					if ip4 := localIP.To4(); ip4 != nil && isIPv4Mapped(localIP) {
						localIP = ip4
					}
				}

				conn := &model.Connection{
					Protocol:   "TCP",
					LocalIP:    localIP,
					LocalPort:  localPort,
					RemoteIP:   remoteIP,
					RemotePort: remotePort,
					State:      stateStr,
					Scope:      classifier.ClassifyScope(remoteIP),
					Inode:      uint64(diagMsg.Inode),
					User:       fmt.Sprintf("%d", diagMsg.UID),
					RXBytes:    uint64(diagMsg.Rqueue),
					TXBytes:    uint64(diagMsg.Wqueue),
				}

				// Parse rtattrs (INET_DIAG_INFO / tcp_info)
				attrOffset := diagMsgSize
				for attrOffset+4 <= len(msgBytes) {
					var rta rtattr
					binary.Read(bytes.NewReader(msgBytes[attrOffset:attrOffset+4]), binary.LittleEndian, &rta)
					if rta.Len < 4 || attrOffset+int(rta.Len) > len(msgBytes) {
						break
					}
					attrData := msgBytes[attrOffset+4 : attrOffset+int(rta.Len)]
					if rta.Type == inetDiagInfo && len(attrData) >= 36 {
						// tcpi_rtt is at offset 32 (uint32 in microseconds)
						rttUs := binary.LittleEndian.Uint32(attrData[32:36])
						conn.RTT = time.Duration(rttUs) * time.Microsecond

						// If tcp_info has tcpi_bytes_acked and tcpi_bytes_received
						if len(attrData) >= 176 {
							bytesAcked := binary.LittleEndian.Uint64(attrData[160:168])
							bytesReceived := binary.LittleEndian.Uint64(attrData[168:176])
							if bytesAcked > 0 || bytesReceived > 0 {
								conn.TXBytes = bytesAcked
								conn.RXBytes = bytesReceived
							}
						}
					}
					attrOffset += (int(rta.Len) + 3) &^ 3
				}

				conns = append(conns, conn)
			}
		}

		offset += (int(h.Len) + 3) &^ 3
	}

	return false, conns, nil
}

func mapTCPState(st uint8) string {
	switch st {
	case tcpEstablished:
		return "ESTABLISHED"
	case tcpSynSent:
		return "SYN_SENT"
	case tcpSynRecv:
		return "SYN_RECV"
	case tcpFinWait1:
		return "FIN_WAIT1"
	case tcpFinWait2:
		return "FIN_WAIT2"
	case tcpTimeWait:
		return "TIME_WAIT"
	case tcpClose:
		return "CLOSE"
	case tcpCloseWait:
		return "CLOSE_WAIT"
	case tcpLastAck:
		return "LAST_ACK"
	case tcpListen:
		return "LISTEN"
	case tcpClosing:
		return "CLOSING"
	default:
		return "UNKNOWN"
	}
}

func isIPv4Mapped(ip net.IP) bool {
	if len(ip) != 16 {
		return false
	}
	for i := 0; i < 10; i++ {
		if ip[i] != 0 {
			return false
		}
	}
	return ip[10] == 0xff && ip[11] == 0xff
}
