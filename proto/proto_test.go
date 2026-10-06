package proto_test

import (
	"errors"
	"testing"

	"github.com/lechandonga/packet-capture-analyzer-go/pcapio"
	"github.com/lechandonga/packet-capture-analyzer-go/pcapio/pcaptest"
	"github.com/lechandonga/packet-capture-analyzer-go/proto"
)

func TestDecode(t *testing.T) {
	frame := func(flags uint8, payload []byte) *pcapio.Record {
		blob := pcaptest.Build(pcapio.LinkEther, 65535, []pcaptest.Frame{
			{SrcIP: "192.0.2.1", DstIP: "198.51.100.2", SrcPort: 5555, DstPort: 8080, Seq: 42, Ack: 99, Flags: flags, Payload: payload},
		}, nil)
		cap, _, err := pcapio.ReadAll(bytesNewReader(blob))
		if err != nil {
			t.Fatal(err)
		}
		return cap.Records[0]
	}

	t.Run("业务:协议解码/以太网IPv4 TCP字段完整", func(t *testing.T) {
		rec := frame(pcaptest.SYN|pcaptest.ACK, nil)
		pk, err := proto.DecodeFrame(pcapio.LinkEther, rec)
		if err != nil {
			t.Fatal(err)
		}
		if pk.IP.Src != "192.0.2.1" || pk.IP.Dst != "198.51.100.2" || pk.IP.Protocol != proto.ProtoTCP {
			t.Fatalf("ip=%+v", pk.IP)
		}
		if pk.TCP.SrcPort != 5555 || pk.TCP.DstPort != 8080 || pk.TCP.Seq != 42 || pk.TCP.Ack != 99 {
			t.Fatalf("tcp=%+v", pk.TCP)
		}
		if !pk.TCP.Flags.Has(proto.TCPSyn) || !pk.TCP.Flags.Has(proto.TCPAck) {
			t.Fatalf("flags=%s", pk.TCP.Flags)
		}
	})

	t.Run("业务:协议解码/snaplen截断TCP头报可区分错误", func(t *testing.T) {
		blob := pcaptest.Build(pcapio.LinkEther, 30, []pcaptest.Frame{
			{SrcIP: "192.0.2.1", DstIP: "198.51.100.2", SrcPort: 1, DstPort: 2, Flags: pcaptest.SYN},
		}, nil)
		cap, _, err := pcapio.ReadAll(bytesNewReader(blob))
		if err != nil {
			t.Fatal(err)
		}
		_, err = proto.DecodeFrame(pcapio.LinkEther, cap.Records[0])
		var de *proto.DecodeError
		if !errors.As(err, &de) || de.Layer != "ip" {
			t.Fatalf("err=%v", err)
		}
		if !errors.Is(err, proto.ErrShortFrame) {
			t.Fatalf("want ErrShortFrame, got %v", err)
		}
	})

	t.Run("业务:协议解码/坏IP版本报不支持", func(t *testing.T) {
		bad := append([]byte{0x60, 0}, make([]byte, 40)...)
		eth := make([]byte, 14)
		eth[12], eth[13] = 0x86, 0xdd
		rec := &pcapio.Record{Data: append(eth, bad...)}
		// Replace version nibble to 5 by hand within IPv4 ethertype.
		eth2 := make([]byte, 14)
		eth2[12], eth2[13] = 0x08, 0x00
		ip := make([]byte, 20)
		ip[0] = 0x55
		rec = &pcapio.Record{Data: append(eth2, ip...)}
		_, err := proto.DecodeFrame(pcapio.LinkEther, rec)
		var de *proto.DecodeError
		if !errors.As(err, &de) || !errors.Is(err, proto.ErrUnsupported) {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("业务:协议解码/数据偏移非法报畸形", func(t *testing.T) {
		rec := frame(pcaptest.PSH|pcaptest.ACK, []byte("abc"))
		rec.Data[14+20+12] = 0x20 // data offset = 2 words (< 20 bytes)
		_, err := proto.DecodeFrame(pcapio.LinkEther, rec)
		var de *proto.DecodeError
		if !errors.As(err, &de) || de.Layer != "tcp" || !errors.Is(err, proto.ErrMalformed) {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("业务:协议解码/IPv6基本头UDP通过", func(t *testing.T) {
		pkt := ipv6UDP()
		eth := make([]byte, 14)
		eth[12], eth[13] = 0x86, 0xdd
		rec := &pcapio.Record{Data: append(eth, pkt...)}
		pk, err := proto.DecodeFrame(pcapio.LinkEther, rec)
		if err != nil {
			t.Fatal(err)
		}
		if pk.IP.Version != 6 || pk.UDP == nil || pk.UDP.DstPort != 53 {
			t.Fatalf("pk=%+v udp=%+v", pk, pk.UDP)
		}
	})
}
