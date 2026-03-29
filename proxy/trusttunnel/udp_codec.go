package trusttunnel

import (
	"encoding/binary"
	"errors"
	stdnet "net"
)

const (
	trustTunnelUDPAddrSize              = 16
	trustTunnelUDPPortSize              = 2
	trustTunnelUDPLengthSize            = 4
	trustTunnelUDPAppNameLenSize        = 1
	trustTunnelUDPRequestFixedNoLength  = 2*(trustTunnelUDPAddrSize+trustTunnelUDPPortSize) + trustTunnelUDPAppNameLenSize
	trustTunnelUDPResponseFixedNoLength = 2 * (trustTunnelUDPAddrSize + trustTunnelUDPPortSize)
)

type trustTunnelUDPRequestPacket struct {
	Source      *stdnet.UDPAddr
	Destination *stdnet.UDPAddr
	AppName     string
	Payload     []byte
}

type trustTunnelUDPResponsePacket struct {
	Source      *stdnet.UDPAddr
	Destination *stdnet.UDPAddr
	Payload     []byte
}

type trustTunnelUDPRequestDecoder struct {
	buf []byte
}

type trustTunnelUDPResponseDecoder struct {
	buf []byte
}

func encodeTrustTunnelUDPRequest(pkt trustTunnelUDPRequestPacket) ([]byte, error) {
	if pkt.Source == nil {
		return nil, errors.New("trusttunnel udp request source is nil")
	}
	if pkt.Destination == nil {
		return nil, errors.New("trusttunnel udp request destination is nil")
	}
	if len(pkt.AppName) > 255 {
		return nil, errors.New("trusttunnel udp request app name is too long")
	}

	src, err := trustTunnelUDPAddrTo16(pkt.Source.IP)
	if err != nil {
		return nil, err
	}
	dst, err := trustTunnelUDPAddrTo16(pkt.Destination.IP)
	if err != nil {
		return nil, err
	}

	totalLength := trustTunnelUDPRequestFixedNoLength + len(pkt.AppName) + len(pkt.Payload)
	out := make([]byte, trustTunnelUDPLengthSize+totalLength)

	binary.BigEndian.PutUint32(out[0:4], uint32(totalLength))
	copy(out[4:20], src[:])
	binary.BigEndian.PutUint16(out[20:22], uint16(pkt.Source.Port))
	copy(out[22:38], dst[:])
	binary.BigEndian.PutUint16(out[38:40], uint16(pkt.Destination.Port))
	out[40] = byte(len(pkt.AppName))
	copy(out[41:41+len(pkt.AppName)], []byte(pkt.AppName))
	copy(out[41+len(pkt.AppName):], pkt.Payload)

	return out, nil
}

func encodeTrustTunnelUDPResponse(pkt trustTunnelUDPResponsePacket) ([]byte, error) {
	if pkt.Source == nil {
		return nil, errors.New("trusttunnel udp response source is nil")
	}
	if pkt.Destination == nil {
		return nil, errors.New("trusttunnel udp response destination is nil")
	}

	src, err := trustTunnelUDPAddrTo16(pkt.Source.IP)
	if err != nil {
		return nil, err
	}
	dst, err := trustTunnelUDPAddrTo16(pkt.Destination.IP)
	if err != nil {
		return nil, err
	}

	totalLength := trustTunnelUDPResponseFixedNoLength + len(pkt.Payload)
	out := make([]byte, trustTunnelUDPLengthSize+totalLength)

	binary.BigEndian.PutUint32(out[0:4], uint32(totalLength))
	copy(out[4:20], src[:])
	binary.BigEndian.PutUint16(out[20:22], uint16(pkt.Source.Port))
	copy(out[22:38], dst[:])
	binary.BigEndian.PutUint16(out[38:40], uint16(pkt.Destination.Port))
	copy(out[40:], pkt.Payload)

	return out, nil
}

func (d *trustTunnelUDPRequestDecoder) Feed(chunk []byte) ([]trustTunnelUDPRequestPacket, error) {
	if len(chunk) > 0 {
		d.buf = append(d.buf, chunk...)
	}

	var out []trustTunnelUDPRequestPacket

	for {
		if len(d.buf) < trustTunnelUDPLengthSize {
			return out, nil
		}

		totalLength := int(binary.BigEndian.Uint32(d.buf[0:4]))
		if totalLength < trustTunnelUDPRequestFixedNoLength {
			return nil, errors.New("trusttunnel udp request frame is too short")
		}

		frameLength := trustTunnelUDPLengthSize + totalLength
		if len(d.buf) < frameLength {
			return out, nil
		}

		frame := d.buf[:frameLength]
		appLen := int(frame[40])
		if totalLength < trustTunnelUDPRequestFixedNoLength+appLen {
			return nil, errors.New("trusttunnel udp request frame has invalid app name length")
		}

		payloadOffset := 41 + appLen
		payload := make([]byte, frameLength-payloadOffset)
		copy(payload, frame[payloadOffset:frameLength])

		pkt := trustTunnelUDPRequestPacket{
			Source: &stdnet.UDPAddr{
				IP:   trustTunnelUDPAddrFrom16(frame[4:20]),
				Port: int(binary.BigEndian.Uint16(frame[20:22])),
			},
			Destination: &stdnet.UDPAddr{
				IP:   trustTunnelUDPAddrFrom16(frame[22:38]),
				Port: int(binary.BigEndian.Uint16(frame[38:40])),
			},
			AppName: string(frame[41 : 41+appLen]),
			Payload: payload,
		}

		out = append(out, pkt)
		d.buf = d.buf[frameLength:]
	}
}

func (d *trustTunnelUDPResponseDecoder) Feed(chunk []byte) ([]trustTunnelUDPResponsePacket, error) {
	if len(chunk) > 0 {
		d.buf = append(d.buf, chunk...)
	}

	var out []trustTunnelUDPResponsePacket

	for {
		if len(d.buf) < trustTunnelUDPLengthSize {
			return out, nil
		}

		totalLength := int(binary.BigEndian.Uint32(d.buf[0:4]))
		if totalLength < trustTunnelUDPResponseFixedNoLength {
			return nil, errors.New("trusttunnel udp response frame is too short")
		}

		frameLength := trustTunnelUDPLengthSize + totalLength
		if len(d.buf) < frameLength {
			return out, nil
		}

		frame := d.buf[:frameLength]
		payload := make([]byte, frameLength-40)
		copy(payload, frame[40:frameLength])

		pkt := trustTunnelUDPResponsePacket{
			Source: &stdnet.UDPAddr{
				IP:   trustTunnelUDPAddrFrom16(frame[4:20]),
				Port: int(binary.BigEndian.Uint16(frame[20:22])),
			},
			Destination: &stdnet.UDPAddr{
				IP:   trustTunnelUDPAddrFrom16(frame[22:38]),
				Port: int(binary.BigEndian.Uint16(frame[38:40])),
			},
			Payload: payload,
		}

		out = append(out, pkt)
		d.buf = d.buf[frameLength:]
	}
}

func trustTunnelUDPAddrTo16(ip stdnet.IP) ([16]byte, error) {
	var out [16]byte

	if ip == nil {
		return out, errors.New("trusttunnel udp ip is nil")
	}

	if v4 := ip.To4(); v4 != nil {
		copy(out[12:], v4)
		return out, nil
	}

	if v6 := ip.To16(); v6 != nil {
		copy(out[:], v6)
		return out, nil
	}

	return out, errors.New("trusttunnel udp ip is invalid")
}

func trustTunnelUDPAddrFrom16(raw []byte) stdnet.IP {
	if len(raw) != 16 {
		return nil
	}

	if trustTunnelUDPIsZeroPaddedIPv4(raw) {
		return stdnet.IPv4(raw[12], raw[13], raw[14], raw[15])
	}

	ip := make(stdnet.IP, 16)
	copy(ip, raw)
	return ip
}

func trustTunnelUDPIsZeroPaddedIPv4(raw []byte) bool {
	if len(raw) != 16 {
		return false
	}
	for i := 0; i < 12; i++ {
		if raw[i] != 0 {
			return false
		}
	}
	return true
}
