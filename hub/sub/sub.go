package sub

import (
	"encoding/base64"
	"fmt"
	"github.com/Dreamacro/clash/config"
	"github.com/Dreamacro/clash/hub/executor"
	"gopkg.in/yaml.v3"
	"reflect"
	//C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"io"
	"net/http"
	"net/url"
	"strings"
)

func Start(subs []config.SubServer) {
	go func() {
		updateConfig(subs)
	}()
}

type proxyInfo map[string]any

func updateConfig(ss []config.SubServer) {
	allProxies := make(map[string][]any)
	for _, s := range ss {
		info, err := getInfo(s.URL)
		if err != nil {
			log.Errorln("get sub from %s err: %s", s.URL, err)
			return
		}
		// 解析数据
		decodeString, err := base64.StdEncoding.DecodeString(info)
		if err != nil {
			log.Errorln("base64 decode err: %s", err)
			return
		}
		proxies := ParseProxy(string(decodeString))
		allProxies[s.Name] = proxies
	}
	// merge config
	mergeConfig := mergeAllConfig(allProxies)
	// 更新配置
	cf, err := executor.ParseWithBytes(mergeConfig)
	if err != nil {
		log.Errorln("parse config err: %s", err)
		return
	}
	executor.ApplyConfig(cf, false)
}

/*
proxies:
  - { name: 'S1', type: trojan, server: 6w7j3p01.mcfront.xyz, port: 31116, password: fb50cf9e-b84e-4b31-b95c-1656c1c08236, udp: true, sni: jp01.lovemc.xyz }
  - { name: 'S2', type: trojan, server: 6w7j3p01.mcfront.xyz, port: 31116, password: fb50cf9e-b84e-4b31-b95c-1656c1c08236, udp: true, sni: jp01.lovemc.xyz }

proxy-groups:
  - { name: all, type: select, proxies: ['best', 'fallback',  'S1', 'S2']  }
  - { name: best, type: url-test, url: "https://api.openai.com", interval: 300, proxies: ['S1', 'S2'] }
  - { name: fallback, type: fallback, url: "https://api.openai.com", interval: 300, proxies: ['S1', 'S2'] }
rules:
  - 'MATCH,all'
*/

type Group struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Proxies  []string `yaml:"proxies"`
	Url      string   `yaml:"url"`
	Interval int      `yaml:"interval"`
}
type meralConfig struct {
	Proxies     []any    `yaml:"proxies"`
	ProxyGroups []Group  `yaml:"proxy-groups"`
	Rules       []string `yaml:"rules"`
}

func mergeAllConfig(ps map[string][]any) []byte {
	c := meralConfig{}
	c.Rules = append(c.Rules, "MATCH,all")

	var proxyNames []string
	for cName, proxies := range ps {
		//proxies = append(proxies, v.Name())
		for _, p := range proxies {
			switch p.(type) {
			case map[string]any:
				pr, _ := p.(map[string]any)
				pName := fmt.Sprintf("(%s)%s", cName, pr["name"])
				pr["name"] = pName
				c.Proxies = append(c.Proxies, p)
				proxyNames = append(proxyNames, pName)
			default:
				log.Warnln("merge config failed, unknown type, p: %v, type: %v", p, reflect.TypeOf(p).Name())
				continue
			}
		}
	}

	c.ProxyGroups = append(c.ProxyGroups, Group{
		Name:    "all",
		Type:    "select",
		Proxies: []string{"best", "fallback"},
	}, Group{
		Name:     "best",
		Type:     "url-test",
		Url:      "https://api.openai.com",
		Interval: 300,
		Proxies:  proxyNames,
	}, Group{
		Name:     "fallback",
		Type:     "fallback",
		Url:      "https://api.openai.com",
		Interval: 300,
		Proxies:  proxyNames,
	})

	data, err := yaml.Marshal(c)
	if err != nil {
		log.Warnln("marshal config err: %s", err)
		return nil
	}
	return data
}

func getInfo(u string) (string, error) {
	if _, err := url.Parse(strings.TrimSpace(u)); err != nil {
		return "", fmt.Errorf("parse err in url %s, %s", u, err)
	}

	resp, err := http.Get(u)
	defer resp.Body.Close()

	if err != nil {
		return "", fmt.Errorf("get sub from %s err: %s", u, err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("get sub from %s, status code: %d", u, resp.StatusCode)
	}

	all, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorln("read sub from %s err: %s", u, err)
		return "", fmt.Errorf("read sub from %s err: %s", u, err)
	}

	return string(all), nil
}
