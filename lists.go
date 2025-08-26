package main

import (
	"errors"
	"log"
	"net"
	"net/url"
	"strings"
)

type User struct {
	name   string
	secret string
}

type Wildcard struct {
	IP  *net.IP
	Net *net.IPNet
}

var userList []User

var allowList []Wildcard
var denyList []Wildcard

func ParseNetmask(in string) (Wildcard, bool) {

	var parseError *net.ParseError

	_, network, err := net.ParseCIDR(in)
	if err == nil {
		return Wildcard{Net: network}, true
	}

	if errors.As(err, &parseError) {
		ip := net.ParseIP(in)
		if ip != nil {
			return Wildcard{IP: &ip}, true
		}
		return Wildcard{}, false
	}

	return Wildcard{}, false

}

func CheckWildcardList(in string, list []Wildcard) bool {
	ip := net.ParseIP(in)
	if ip == nil {
		return false
	}

	for _, entry := range list {
		switch true {
		case entry.IP != nil:
			if ip.Equal(*entry.IP) {
				return true
			}
		case entry.Net != nil:
			if entry.Net.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func LogWildcard(w Wildcard) {
	switch true {
	case w.IP != nil:
		log.Printf("- %s", w.IP.String())
	case w.Net != nil:
		log.Printf("- %s", w.Net.String())
	}
}

// Parse allow/deny/user lists.
func ParseLists() {
	for _, ip := range cfg.Allow {
		if thatIP, ok := ParseNetmask(ip); ok {
			allowList = append(allowList, thatIP)
		}
	}

	for _, ip := range cfg.Deny {
		if thatIP, ok := ParseNetmask(ip); ok {
			denyList = append(denyList, thatIP)
		}
	}

	if len(denyList) > 0 {
		log.Printf("deny list:")
		for _, entry := range denyList {
			LogWildcard(entry)
		}
	}

	if len(allowList) > 0 {
		log.Printf("allow list:")
		for _, entry := range allowList {
			LogWildcard(entry)
		}
	}

	// Parse the users and extract their secrets.
	for _, user := range cfg.Users {
		url, err := url.Parse(user)
		if err != nil {
			log.Printf("error parsing a user: %s", err.Error())
			continue
		}
		secret := url.Query().Get("secret")

		username := ""
		chunks := strings.Split(url.Path, ":")
		if len(chunks) == 2 {
			username = chunks[1]
		}

		if secret != "" && username != "" {
			userList = append(userList, User{
				name:   username,
				secret: secret,
			})
		}
	}
	if len(userList) > 0 {
		log.Printf("user list:")
		for _, user := range userList {
			log.Printf("- %s", user.name)
		}
	}

	log.Printf("%d users known, %d IPs explicitly allowed, %d explicitly denied.",
		len(userList), len(allowList), len(denyList))

}
