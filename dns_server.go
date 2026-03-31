package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const baseURL string = "ba.tilhempel.info."
const addr = "0.0.0.0"
const port = 53
const timeout = 5000     // in ms
const sleepCycle = 10000 // in ms

var ip string
var lastClean time.Time

type IP struct {
	Query string
}
type probeData struct {
	Resolver      string
	tokenLength   int
	lastSeen      time.Time
	tokenSequence []string
	tokens        map[string]bool
}

var (
	probes      = make(map[string]probeData)
	probesMutex = sync.RWMutex{}
)

func cleanProbes() {
	probesMutex.Lock()
	lastClean = time.Now()
	if time.Since(lastClean).Milliseconds() > sleepCycle {
		for k, v := range probes {
			if time.Since(v.lastSeen).Milliseconds() > timeout {
				delete(probes, k)
			}
		}
	}
	probesMutex.Unlock()
}

func ipFromHexString(s string) string {
	if len(s) != 8 {
		log.Fatalln("String provided is not an hex encoded ip")
	}
	var ip string = ""
	for i := 0; i < 4; i++ {
		x, err := strconv.ParseInt(s[2*i:2*i+2], 16, 64)
		if err != nil {
			log.Fatalf("Couldn't parse Hex to int for IP: %v", err.Error())
		}
		ip += strconv.FormatInt(x, 10) + "."
	}
	return strings.TrimSuffix(ip, ".")
}

func getPublicIP() string {
	req, err := http.Get("http://ip-api.com/json/")
	if err != nil {
		log.Fatalf("Could not get Public IP: %v", err.Error())
	}
	defer req.Body.Close()

	res, err := io.ReadAll(req.Body)
	if err != nil {
		log.Fatalf("Could not get Public IP: %v", err.Error())
	}
	var ip IP
	json.Unmarshal(res, &ip)
	return ip.Query
}

func testA(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question[0].Name) <= len(baseURL) || !strings.Contains(strings.ToLower(r.Question[0].Name), baseURL) {
		m.SetRcode(r, dns.RcodeNameError)
	} else {
		tokenSeq := r.Question[0].Name[:len(r.Question[0].Name)-len(baseURL)-1]
		tokens := strings.Split(tokenSeq, ".")
		idToken := tokens[len(tokens)-1]

		probesMutex.Lock()
		probe, ok := probes[idToken]
		probesMutex.Unlock()

		if ok {
			for _, tok := range tokens {
				probe.tokens[tok] = true
			}
			if strings.Join(probe.tokenSequence, ".") != tokenSeq {
				if len(tokenSeq) > len(strings.Join(probe.tokenSequence, ".")) {
					fmt.Println(r.Question[0])
					fmt.Println(tokenSeq, " ", probe.tokenSequence)
					newTokens := tokenSeq[:len(tokenSeq)-len(strings.Join(probe.tokenSequence, "."))-1]
					probe.tokenSequence = slices.Insert(probe.tokenSequence, 0, newTokens)
				}
			}
			probe.lastSeen = time.Now()

			probesMutex.Lock()
			probes[idToken] = probe
			probesMutex.Unlock()
		} else if len(idToken) > 10 {
			// Token to identify the probe run:
			// XXXXXXXX | XX | XXXX... (pipes just for visualisation)
			// IPv4 of Resolver (Hex) | max token depth (int) | randomized numbers to circumvent caches (length loosly dependent on number of runs per resolver)

			tokenLen, err := strconv.ParseInt(idToken[8:10], 10, 64)
			if err != nil {
				fmt.Println(idToken)
				log.Fatalf("Couldn't parse token length: %v", err.Error())
			}
			t := make(map[string]bool)
			for _, tok := range tokens {
				t[tok] = true
			}
			probesMutex.Lock()
			probes[idToken] = probeData{
				Resolver:      ipFromHexString(idToken[0:8]),
				tokenLength:   int(tokenLen),
				lastSeen:      time.Now(),
				tokenSequence: []string{tokenSeq},
				tokens:        t,
			}
			probesMutex.Unlock()
		}

		probesMutex.Lock()
		probe = probes[idToken]
		probesMutex.Unlock()

		if len(probe.tokens) == probe.tokenLength {
			rr, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN TXT \"%s\"", r.Question[0].Name, strings.Join(probe.tokenSequence, "|")))
			m.Answer = append(m.Answer, rr)
		} else {
			rr, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN A %s", r.Question[0].Name, ip))
			m.Answer = append(m.Answer, rr)
		}
	}

	if err := w.WriteMsg(m); err != nil {
		log.Fatalf("Write error: %v", err.Error())
	}

	cleanProbes()
}

func main() {
	ip = getPublicIP()

	dns.HandleFunc(".", testA)
	server := &dns.Server{Addr: addr + ":" + strconv.Itoa(port), Net: "udp"}
	fmt.Println("DNS server listining on:", addr, ":", port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
