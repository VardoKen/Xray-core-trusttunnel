package tcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
)

const (
	quicVersion1              = 0x00000001
	quicVersion2              = 0x6b3343cf
	h3ClientHelloNeedBytes    = 38
	h3ClientRandomEntryTTL    = 5 * time.Minute
	h3ClientInitialPacketType = 0x0
	h3v2InitialPacketType     = 0x1
)

var (
	quicInitialSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicInitialSaltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

type h3ClientRandomTracker struct {
	mu     sync.Mutex
	states map[string]*h3ClientRandomState
}

type h3ClientRandomState struct {
	prefix       []byte
	chunks       map[uint64][]byte
	clientRandom string
	updatedAt    time.Time
}

type h3CryptoFragment struct {
	offset uint64
	data   []byte
}

type h3ClientRandomPacketConn struct {
	net.PacketConn
	tracker *h3ClientRandomTracker
}

func newH3ClientRandomTracker() *h3ClientRandomTracker {
	return &h3ClientRandomTracker{
		states: make(map[string]*h3ClientRandomState),
	}
}

func (t *h3ClientRandomTracker) Feed(addr net.Addr, datagram []byte) {
	if addr == nil || len(datagram) == 0 {
		return
	}

	fragments := parseH3InitialCryptoFragments(datagram)
	if len(fragments) == 0 {
		return
	}

	key := addr.String()
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	t.cleanupLocked(now)

	st := t.states[key]
	if st == nil {
		st = &h3ClientRandomState{
			chunks: make(map[uint64][]byte),
		}
		t.states[key] = st
	}
	st.updatedAt = now

	for _, f := range fragments {
		st.add(f.offset, f.data)
	}
}

func (t *h3ClientRandomTracker) Get(key string) string {
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	t.cleanupLocked(now)

	st := t.states[key]
	if st == nil {
		return ""
	}
	st.updatedAt = now
	return st.clientRandom
}

func (t *h3ClientRandomTracker) cleanupLocked(now time.Time) {
	for k, st := range t.states {
		if now.Sub(st.updatedAt) > h3ClientRandomEntryTTL {
			delete(t.states, k)
		}
	}
}

func (s *h3ClientRandomState) add(offset uint64, data []byte) {
	if s.clientRandom != "" || len(data) == 0 {
		return
	}
	if s.chunks == nil {
		s.chunks = make(map[uint64][]byte)
	}

	if offset < uint64(len(s.prefix)) {
		overlap := uint64(len(s.prefix)) - offset
		if overlap >= uint64(len(data)) {
			return
		}
		data = data[overlap:]
		offset = uint64(len(s.prefix))
	}
	if len(data) == 0 {
		return
	}

	buf := append([]byte(nil), data...)

	if offset == uint64(len(s.prefix)) {
		s.prefix = append(s.prefix, buf...)
		s.merge()
		s.tryExtract()
		return
	}

	if old, ok := s.chunks[offset]; ok && len(old) >= len(buf) {
		return
	}
	s.chunks[offset] = buf
	s.merge()
	s.tryExtract()
}

func (s *h3ClientRandomState) merge() {
	for {
		key := uint64(len(s.prefix))
		chunk, ok := s.chunks[key]
		if !ok {
			return
		}
		s.prefix = append(s.prefix, chunk...)
		delete(s.chunks, key)
	}
}

func (s *h3ClientRandomState) tryExtract() {
	if s.clientRandom != "" || len(s.prefix) < h3ClientHelloNeedBytes {
		return
	}
	if s.prefix[0] != 0x01 {
		return
	}

	handshakeLen := int(s.prefix[1])<<16 | int(s.prefix[2])<<8 | int(s.prefix[3])
	if handshakeLen+4 < h3ClientHelloNeedBytes {
		return
	}

	s.clientRandom = hex.EncodeToString(s.prefix[6:38])
	s.chunks = nil
}

func (c *h3ClientRandomPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 && addr != nil {
		c.tracker.Feed(addr, append([]byte(nil), p[:n]...))
	}
	return n, addr, err
}

func parseH3InitialCryptoFragments(datagram []byte) []h3CryptoFragment {
	fragments, _, ok := decodeInitialPacketCryptoFragments(datagram)
	if !ok {
		return nil
	}
	return fragments
}

func decodeInitialPacketCryptoFragments(packet []byte) ([]h3CryptoFragment, int, bool) {
	if len(packet) < 7 {
		return nil, 0, false
	}
	firstByte := packet[0]
	if firstByte&0x80 == 0 || firstByte&0x40 == 0 {
		return nil, 0, false
	}

	version := binary.BigEndian.Uint32(packet[1:5])

	var salt []byte
	var initialType byte
	switch version {
	case quicVersion1:
		salt = quicInitialSaltV1
		initialType = h3ClientInitialPacketType
	case quicVersion2:
		salt = quicInitialSaltV2
		initialType = h3v2InitialPacketType
	default:
		return nil, 0, false
	}

	if ((firstByte >> 4) & 0x3) != initialType {
		return nil, 0, false
	}

	pos := 5

	dcidLen := int(packet[pos])
	pos++
	if len(packet) < pos+dcidLen+1 {
		return nil, 0, false
	}
	dcid := append([]byte(nil), packet[pos:pos+dcidLen]...)
	pos += dcidLen

	scidLen := int(packet[pos])
	pos++
	if len(packet) < pos+scidLen {
		return nil, 0, false
	}
	pos += scidLen

	tokenLen, tokenLenSize, ok := readQUICVarInt(packet[pos:])
	if !ok {
		return nil, 0, false
	}
	pos += tokenLenSize
	if len(packet) < pos+int(tokenLen) {
		return nil, 0, false
	}
	pos += int(tokenLen)

	packetLen, packetLenSize, ok := readQUICVarInt(packet[pos:])
	if !ok {
		return nil, 0, false
	}
	pos += packetLenSize

	totalLen := pos + int(packetLen)
	if len(packet) < totalLen {
		return nil, 0, false
	}

	pnOffset := pos
	sampleOffset := pnOffset + 4
	if totalLen < sampleOffset+16 {
		return nil, totalLen, false
	}

	key, iv, hp, ok := deriveInitialSecrets(salt, dcid)
	if !ok {
		return nil, totalLen, false
	}

	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, totalLen, false
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, packet[sampleOffset:sampleOffset+16])

	unprotectedFirstByte := firstByte ^ (mask[0] & 0x0f)
	pnLen := int(unprotectedFirstByte&0x03) + 1
	if pnOffset+pnLen > totalLen {
		return nil, totalLen, false
	}

	header := append([]byte(nil), packet[:pnOffset+pnLen]...)
	header[0] = unprotectedFirstByte
	for i := 0; i < pnLen; i++ {
		header[pnOffset+i] ^= mask[i+1]
	}

	packetNumber := decodePacketNumber(header[pnOffset : pnOffset+pnLen])

	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	var pnBuf [8]byte
	binary.BigEndian.PutUint64(pnBuf[:], packetNumber)
	for i := 0; i < len(nonce) && i < len(pnBuf); i++ {
		nonce[len(nonce)-1-i] ^= pnBuf[len(pnBuf)-1-i]
	}

	block, err = aes.NewCipher(key)
	if err != nil {
		return nil, totalLen, false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, totalLen, false
	}

	ciphertext := packet[pnOffset+pnLen : totalLen]
	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, totalLen, false
	}

	return parseCryptoFrames(plaintext), totalLen, true
}

func parseCryptoFrames(payload []byte) []h3CryptoFragment {
	var out []h3CryptoFragment
	pos := 0

	for pos < len(payload) {
		frameType, n, ok := readQUICVarInt(payload[pos:])
		if !ok {
			return out
		}
		pos += n

		switch frameType {
		case 0x00:
			continue
		case 0x01:
			continue
		case 0x02, 0x03:
			nextPos, ok := skipACKFrame(payload, pos, frameType == 0x03)
			if !ok {
				return out
			}
			pos = nextPos
		case 0x06:
			offset, n, ok := readQUICVarInt(payload[pos:])
			if !ok {
				return out
			}
			pos += n

			length, n, ok := readQUICVarInt(payload[pos:])
			if !ok {
				return out
			}
			pos += n

			if len(payload) < pos+int(length) {
				return out
			}

			out = append(out, h3CryptoFragment{
				offset: offset,
				data:   append([]byte(nil), payload[pos:pos+int(length)]...),
			})
			pos += int(length)
		case 0x1c, 0x1d:
			return out
		default:
			return out
		}
	}

	return out
}

func skipACKFrame(payload []byte, pos int, ecn bool) (int, bool) {
	for i := 0; i < 4; i++ {
		_, n, ok := readQUICVarInt(payload[pos:])
		if !ok {
			return 0, false
		}
		pos += n
	}

	rangeCount, n, ok := readQUICVarInt(payload[pos-2:])
	if !ok {
		rangeCount, n, ok = readQUICVarInt(payload[pos-1:])
		if !ok {
			return 0, false
		}
		_ = n
	}

	_ = rangeCount

	rc, n, ok := readQUICVarIntAt(payload, pos)
	if !ok {
		return 0, false
	}
	pos += n

	for i := uint64(0); i < rc; i++ {
		_, n, ok := readQUICVarIntAt(payload, pos)
		if !ok {
			return 0, false
		}
		pos += n

		_, n, ok = readQUICVarIntAt(payload, pos)
		if !ok {
			return 0, false
		}
		pos += n
	}

	if ecn {
		for i := 0; i < 3; i++ {
			_, n, ok := readQUICVarIntAt(payload, pos)
			if !ok {
				return 0, false
			}
			pos += n
		}
	}

	return pos, true
}

func readQUICVarInt(b []byte) (uint64, int, bool) {
	return readQUICVarIntAt(b, 0)
}

func readQUICVarIntAt(b []byte, pos int) (uint64, int, bool) {
	if len(b) <= pos {
		return 0, 0, false
	}

	first := b[pos]
	var size int
	switch first >> 6 {
	case 0:
		size = 1
	case 1:
		size = 2
	case 2:
		size = 4
	default:
		size = 8
	}

	if len(b) < pos+size {
		return 0, 0, false
	}

	var v uint64
	for i := 0; i < size; i++ {
		v = (v << 8) | uint64(b[pos+i])
	}
	v &= ^(uint64(0xc0) << uint((size-1)*8))

	return v, size, true
}

func decodePacketNumber(b []byte) uint64 {
	var pn uint64
	for _, x := range b {
		pn = (pn << 8) | uint64(x)
	}
	return pn
}

func deriveInitialSecrets(salt, dcid []byte) ([]byte, []byte, []byte, bool) {
	initialSecret := hkdfExtract(salt, dcid)
	clientSecret := hkdfExpandLabel(initialSecret, "client in", 32)
	key := hkdfExpandLabel(clientSecret, "quic key", 16)
	iv := hkdfExpandLabel(clientSecret, "quic iv", 12)
	hp := hkdfExpandLabel(clientSecret, "quic hp", 16)
	return key, iv, hp, true
}

func hkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	fullLabel := append([]byte("tls13 "), []byte(label)...)
	info := make([]byte, 4+len(fullLabel))
	binary.BigEndian.PutUint16(info[:2], uint16(length))
	info[2] = byte(len(fullLabel))
	copy(info[3:], fullLabel)
	info[3+len(fullLabel)] = 0
	return hkdfExpand(secret, info, length)
}

func hkdfExpand(secret, info []byte, length int) []byte {
	var out []byte
	var prev []byte
	counter := byte(1)

	for len(out) < length {
		h := hmac.New(sha256.New, secret)
		if len(prev) > 0 {
			h.Write(prev)
		}
		h.Write(info)
		h.Write([]byte{counter})
		prev = h.Sum(nil)
		out = append(out, prev...)
		counter++
	}

	return out[:length]
}
