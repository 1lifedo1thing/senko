// reference server for the vless encryption interop test. it runs the xray
// server handshake from the pinned core checkout (SENKO_CORE_SRC) behind a
// local listener and echoes application bytes, so the C client is checked
// against an implementation it shares no code with.
//
//   vlenc_oracle -mode native|xorpub|random -rtt 0rtt|1rtt -keys x,m -seconds 600 [-padding 100-111-1111.75-0-111.50-0-3333]
//
// stdout: "ENC <client encryption string>" then "PORT <n>"
package main

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/xtls/xray-core/proxy/vless/encryption"
)

func main() {
	mode := flag.String("mode", "native", "native|xorpub|random")
	rtt := flag.String("rtt", "1rtt", "0rtt|1rtt")
	kinds := flag.String("keys", "x", "key chain: x = x25519, m = ml-kem-768, comma separated")
	seconds := flag.Int64("seconds", 0, "ticket lifetime, 0 refuses 0rtt")
	padding := flag.String("padding", "", "padding spec")
	gen := flag.Bool("gen", false, "print the client and server strings (ENC, DEC) and exit, for a real xray inbound")
	flag.Parse()

	var xor uint32
	switch *mode {
	case "xorpub":
		xor = 1
	case "random":
		xor = 2
	}

	var skeys [][]byte
	var ckeys, dkeys []string
	for _, k := range strings.Split(*kinds, ",") {
		switch k {
		case "x":
			priv := make([]byte, 32)
			rand.Read(priv)
			pk, err := ecdh.X25519().NewPrivateKey(priv)
			if err != nil {
				panic(err)
			}
			skeys = append(skeys, priv)
			dkeys = append(dkeys, base64.RawURLEncoding.EncodeToString(priv))
			ckeys = append(ckeys, base64.RawURLEncoding.EncodeToString(pk.PublicKey().Bytes()))
		case "m":
			seed := make([]byte, 64)
			rand.Read(seed)
			dk, err := mlkem.NewDecapsulationKey768(seed)
			if err != nil {
				panic(err)
			}
			skeys = append(skeys, seed)
			dkeys = append(dkeys, base64.RawURLEncoding.EncodeToString(seed))
			ckeys = append(ckeys, base64.RawURLEncoding.EncodeToString(dk.EncapsulationKey().Bytes()))
		default:
			panic("unknown key kind " + k)
		}
	}

	if *gen {
		dec := fmt.Sprintf("mlkem768x25519plus.%s.%ds", *mode, *seconds)
		enc := "mlkem768x25519plus." + *mode + "." + *rtt
		if *padding != "" {
			dec += "." + *padding
			enc += "." + *padding
		}
		fmt.Println("ENC", enc+"."+strings.Join(ckeys, "."))
		fmt.Println("DEC", dec+"."+strings.Join(dkeys, "."))
		return
	}

	inst := &encryption.ServerInstance{}
	if err := inst.Init(skeys, xor, *seconds, 0, *padding); err != nil {
		panic(err)
	}

	enc := "mlkem768x25519plus." + *mode + "." + *rtt
	if *padding != "" {
		enc += "." + *padding
	}
	enc += "." + strings.Join(ckeys, ".")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Println("ENC", enc)
	fmt.Println("PORT", ln.Addr().(*net.TCPAddr).Port)
	os.Stdout.Sync()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			c, err := inst.Handshake(conn, nil)
			if err != nil {
				fmt.Fprintln(os.Stderr, "HSERR", err)
				return
			}
			buf := make([]byte, 65536)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					if _, werr := c.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					if err != io.EOF {
						fmt.Fprintln(os.Stderr, "RDERR", err)
					}
					return
				}
			}
		}()
	}
}
