package doh

import (
	dns_resolver "github.com/Focinfi/go-dns-resolver"
	
	"errors"
	"sync"

	"regexp"
	
	"github.com/babolivier/go-doh-client"
)

var resolver *doh.Resolver
var once sync.Once
var isNodoh bool = false
var dns_server string

func Init(dns string, nodoh bool) {
	if nodoh {
		isNodoh = true
		dns_resolver.Config.SetTimeout(uint(5))
		dns_resolver.Config.RetryTimes = uint(2)
		dns_server = dns
	} else {
		getInstance().Host = dns
	}
}

func Lookup(domain string) (string, bool, error) {
	ipRegex := "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

	if r, _ := regexp.MatchString(ipRegex, domain); r {
		if r, _ := regexp.MatchString("^127.0.0", domain); r {
			return "", isNodoh, errors.New(" Don't resolve loopback")
		}
		if r, _ := regexp.MatchString("^0.0.0", domain); r {
			return "", isNodoh, errors.New(" Don't resolve loopback")
		}
		return domain, isNodoh, nil
	}
	
	if isNodoh {
		if results, err := dns_resolver.Exchange(domain, dns_server+":53", dns_resolver.TypeA); err == nil {
			if len(results) < 1 {
				return "", isNodoh, errors.New(" couldn't resolve the domain or blocked by dns server")
			}
			for _, r := range results {
				if r_content, _ := regexp.MatchString(ipRegex, r.Content); r_content {
					return r.Content, isNodoh, nil
				}
			}
			return "", isNodoh, errors.New(" couldn't get type A of domain")
		} else {
			return "", isNodoh, err
		}
	} else {
		a, _, err := resolver.LookupA(domain)
		if err != nil {
			return "", isNodoh, err
		}

		if len(a) < 1 {
			return "", isNodoh, errors.New(" couldn't resolve the domain")
		}

		ip := a[0].IP4

		return ip, isNodoh, nil
	}
}

func getInstance() *doh.Resolver {
	once.Do(func() {
		resolver = &doh.Resolver{
			Host:  "",
			Class: doh.IN,
		}
	})

	return resolver
}
