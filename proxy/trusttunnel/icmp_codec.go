package trusttunnel

import (
	"encoding/binary"
	"errors"
	stdnet "net"
)

const (
	trustTunnelICMPAddrSize     = 16
	trustTunnelICMPIDSize       = 2
	trustTunnelICMPSeqSize      = 2
	trustTunnelICMPTTLSize      = 1
	trustTunnelICMPDataSizeSize = 2
	trustTunnelICMPTypeSize     = 1
	trustTunnelICMPCodeSize     = 1
	trustTunnelICMPRequestSize  = trustTunnelICMPIDSize + trustTunnelICMPAddrSize + trustTunnelICMPSeqSize + trustTunnelICMPTTLSize + trustTunnelICMPDataSizeSize
	trustTunnelICMPResponseSize = trustTunnelICMPIDSize + trustTunnelICMPAddrSize + trustTunnelICMPTypeSize + trustTunnelICMPCodeSize + trustTunnelICMPSeqSize
)

type trustTunnelICMPRequestPacket struct {
	ID          uint16
	Destination stdnet.IP
	Sequence    uint16
	TTL         uint8
	DataSize    uint16
}

type trustTunnelICMPReplyPacket struct {
	ID       uint16
	Source   stdnet.IP
	Type     uint8
	Code     uint8
	Sequence uint16
}

type trustTunnelICMPRequestDecoder struct {
	buf []byte
}

func encodeTrustTunnelICMPRequest(pkt trustTunnelICMPRequestPacket) ([]byte, error) {
	addr, err := trustTunnelUDPAddrTo16(pkt.Destination)
	if err != nil {
		return nil, err
	}

	out := make([]byte, trustTunnelICMPRequestSize)
	binary.BigEndian.PutUint16(out[0:2], pkt.ID)
	copy(out[2:18], addr[:])
	binary.BigEndian.PutUint16(out[18:20], pkt.Sequence)
	out[20] = pkt.TTL
	binary.BigEndian.PutUint16(out[21:23], pkt.DataSize)
	return out, nil
}

func encodeTrustTunnelICMPReply(pkt trustTunnelICMPReplyPacket) ([]byte, error) {
	addr, err := trustTunnelUDPAddrTo16(pkt.Source)
	if err != nil {
		return nil, err
	}

	out := make([]byte, trustTunnelICMPResponseSize)
	binary.BigEndian.PutUint16(out[0:2], pkt.ID)
	copy(out[2:18], addr[:])
	out[18] = pkt.Type
	out[19] = pkt.Code
	binary.BigEndian.PutUint16(out[20:22], pkt.Sequence)
	return out, nil
}

func (d *trustTunnelICMPRequestDecoder) Feed(chunk []byte) ([]trustTunnelICMPRequestPacket, error) {
	if len(chunk) > 0 {
		d.buf = append(d.buf, chunk...)
	}

	var out []trustTunnelICMPRequestPacket
	for {
		if len(d.buf) < trustTunnelICMPRequestSize {
			return out, nil
		}

		frame := d.buf[:trustTunnelICMPRequestSize]
		pkt := trustTunnelICMPRequestPacket{
			ID:          binary.BigEndian.Uint16(frame[0:2]),
			Destination: trustTunnelUDPAddrFrom16(frame[2:18]),
			Sequence:    binary.BigEndian.Uint16(frame[18:20]),
			TTL:         frame[20],
			DataSize:    binary.BigEndian.Uint16(frame[21:23]),
		}
		if pkt.Destination == nil {
			return nil, errors.New("trusttunnel icmp destination is invalid")
		}

		out = append(out, pkt)
		d.buf = d.buf[trustTunnelICMPRequestSize:]
	}
}
