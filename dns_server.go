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
	tokens        *sync.Map
	currTokenNum  int
}

var (
	probes      = make(map[string]probeData)
	probesMutex = sync.RWMutex{}
)

func cleanProbes() {
	probesMutex.Lock()
	fmt.Println("len before clean:", len(probes))
	lastClean = time.Now()
	if time.Since(lastClean).Milliseconds() > sleepCycle {
		for k, v := range probes {
			if time.Since(v.lastSeen).Milliseconds() > timeout {
				delete(probes, k)
			}
		}
	}
	fmt.Println("len after clean:", len(probes))
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

// handle incoming dns request
func requestResponse(w dns.ResponseWriter, r *dns.Msg) (dns.ResponseWriter, *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	requestedDomain := strings.ToLower(r.Question[0].Name)

	// check if requested Domain is longer than base domain and ends in the base domain
	if len(requestedDomain) <= len(baseURL) || requestedDomain[len(requestedDomain)-len(baseURL):] != baseURL {
		m.SetRcode(r, dns.RcodeNameError)
		return w, m
	}

	tokenSeq := requestedDomain[:len(requestedDomain)-len(baseURL)-1]
	tokens := strings.Split(tokenSeq, ".")
	idToken := tokens[len(tokens)-1]

	// TODO: check for valid id token
	if len(idToken) < 10 {
		m.SetRcode(r, dns.RcodeRefused)
		return w, m
	}

	probesMutex.Lock()
	probe, ok := probes[idToken]

	// check if this probe (identified by id Token) has sent a request before
	if ok {
		probeDomain := strings.Join(probe.tokenSequence, ".")

		// new request is longer than the longest recorded one and contains said longest requested domain --> more information
		// should occur if qmin is used
		// some RR are sending shorter domains inbetween longer ones
		// i've seen one that even does qmin inverse (so send fqdn first und remove one label with each successive request) -> idk why?!
		if len(probeDomain) < len(tokenSeq) && strings.Contains(tokenSeq, probeDomain) {
			newSeq := tokenSeq[:len(tokenSeq)-len(probeDomain)-1]

			probe.currTokenNum = 0
			for _, tok := range tokens {
				probe.tokens.Store(tok, true)
				probe.currTokenNum++
			}
			probe.tokenSequence = slices.Insert(probe.tokenSequence, 0, newSeq)
		}
		probe.lastSeen = time.Now()
	} else {
		// first time this domain is requested
		// create entry in probes map

		// Label to identify the probe run:
		// XXXXXXXX | XX | XXXX... (pipes just for visualisation)
		// IPv4 of Resolver (Hex) | max token depth (int) | randomized numbers to circumvent caches (length loosly dependent on number of runs per resolver)

		tokenLen, err := strconv.ParseInt(idToken[8:10], 10, 64)
		if err != nil {
			log.Fatalf("Couldn't parse token length: %v", err.Error())
		}
		var t sync.Map
		numTokens := 0
		for _, tok := range tokens {
			t.Store(tok, true)
			numTokens++
		}
		probe = probeData{
			Resolver:      ipFromHexString(idToken[0:8]),
			tokenLength:   int(tokenLen),
			lastSeen:      time.Now(),
			tokenSequence: []string{tokenSeq},
			tokens:        &t,
			currTokenNum:  numTokens,
		}
	}
	probesMutex.Unlock()

	if probe.currTokenNum == probe.tokenLength {
		rr, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN TXT \"%s\"", r.Question[0].Name, strings.Join(probe.tokenSequence, "|")))
		m.Answer = append(m.Answer, rr)
	} else {
		rr, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN A %s", r.Question[0].Name, ip))
		m.Answer = append(m.Answer, rr)

		probesMutex.Lock()
		probes[idToken] = probe
		probesMutex.Unlock()
	}

	cleanProbes()
	return w, m
}

func responder(w dns.ResponseWriter, r *dns.Msg) {
	var m *dns.Msg
	w, m = requestResponse(w, r)

	if err := w.WriteMsg(m); err != nil {
		log.Fatalf("Write error: %v", err.Error())
	}
}

func main() {
	ip = getPublicIP()

	dns.HandleFunc(".", responder)
	server := &dns.Server{Addr: addr + ":" + strconv.Itoa(port), Net: "udp"}
	fmt.Println("DNS server listining on:", addr, ":", port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
