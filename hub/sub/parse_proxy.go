package sub

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cast"
)

const (
	ssrHeader      = "ssr://"
	vmessHeader    = "vmess://"
	ssHeader       = "ss://"
	trojanHeader   = "trojan://"
	hysteriaHeader = "hysteria://"
)

var (
	//ssReg      = regexp.MustCompile(`(?m)ss://(\w+)@([^:]+):(\d+)\?plugin=([^;]+);\w+=(\w+)(?:;obfs-host=)?([^#]+)?#(.+)`)
	ssReg2 = regexp.MustCompile(`(?m)([\-0-9a-z]+):(.+)@(.+):(\d+)(.+)?#(.+)`)
	ssReg  = regexp.MustCompile(`(?m)([^@]+)(@.+)?#?(.+)?`)
)

func ParseProxy(content string) (proxies []any) {
	// try unmarshal clash config
	var c Clash
	if err := yaml.Unmarshal([]byte(content), &c); err == nil {
		for _, pg := range c.Proxies {
			proxies = append(proxies, pg)
		}
		return proxies
	}

	// ssd
	if strings.Contains(content, "airport") {
		ssSlice := ssdConf(content)
		for _, ss := range ssSlice {
			if ss.Name != "" {
				proxies = append(proxies, ss)
			}
		}
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		proxy, err := parseProxy(line)
		if err != nil {
			log.Printf("parse proxy failed, err: %v, line: %v", err, line)
			continue
		}
		if proxy != nil {
			proxies = append(proxies, proxy)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("parse proxy failed, err: %v", err)
	}

	return proxies
}

func subProtocolBody(proxy string, prefix string) string {
	return strings.TrimSpace(proxy[len(prefix):])
}

// every sub method could not return nil, nil
// if parse failed, return (nil, error)
func parseProxy(proxy string) (any, error) {
	switch {
	case strings.HasPrefix(proxy, ssrHeader):
		//return ssrConf(subProtocolBody(proxy, ssrHeader))
	case strings.HasPrefix(proxy, vmessHeader):
		//return v2rConf(subProtocolBody(proxy, vmessHeader))
	case strings.HasPrefix(proxy, ssHeader):
		return ssConf(proxy)
	case strings.HasPrefix(proxy, trojanHeader):
		//return trojanConf(proxy)
	case strings.HasPrefix(proxy, hysteriaHeader):
		//return hysteriaConf(proxy)
	}

	return nil, fmt.Errorf("unknown proxy type")
}

type ClashHysteria struct {
	Name                string   `yaml:"name"`
	Type                string   `yaml:"type"`
	Server              string   `yaml:"server"`
	Port                int      `yaml:"port"`
	AuthStr             string   `yaml:"auth-str"`
	Obfs                string   `yaml:"obfs"`
	ObfsParams          string   `yaml:"obfs-param"`
	Alpn                []string `yaml:"alpn"`
	Protocol            string   `yaml:"protocol"`
	Up                  string   `yaml:"up"`
	Down                string   `yaml:"down"`
	Sni                 string   `yaml:"sni"`
	SkipCertVerify      bool     `yaml:"skip-cert-verify"`
	RecvWindowConn      int      `yaml:"recv-window-conn"`
	RecvWindow          int      `yaml:"recv-window"`
	Ca                  string   `yaml:"ca"`
	CaStr               string   `yaml:"ca-str"`
	DisableMtuDiscovery bool     `yaml:"disable_mtu_discovery"`
	Fingerprint         string   `yaml:"fingerprint"`
	FastOpen            bool     `yaml:"fast-open"`
}

// https://hysteria.network/docs/uri-scheme/
// hysteria://host:port?protocol=udp&auth=123456&peer=sni.domain&insecure=1&upmbps=100&downmbps=100&alpn=hysteria&obfs=xplus&obfsParam=123456#remarks
func hysteriaConf(body string) (map[string]any, error) {
	u, err := url.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("parse hysteria failed, err: %v", err)
	}

	query := u.Query()
	c := &ClashHysteria{
		Name:                u.Fragment,
		Type:                "hysteria",
		Server:              u.Hostname(),
		Port:                cast.ToInt(u.Port()),
		AuthStr:             query.Get("auth"),
		Obfs:                query.Get("obfs"),
		Alpn:                []string{query.Get("alpn")},
		Protocol:            query.Get("protocol"),
		Up:                  query.Get("upmbps"),
		Down:                query.Get("downmbps"),
		Sni:                 query.Get("peer"),
		SkipCertVerify:      cast.ToBool(query.Get("insecure")),
		RecvWindowConn:      cast.ToInt(query.Get("recv-window-conn")),
		RecvWindow:          cast.ToInt(query.Get("recv-window")),
		Ca:                  query.Get("ca"),
		CaStr:               query.Get("ca-str"),
		DisableMtuDiscovery: cast.ToBool(query.Get("disable_mtu_discovery")),
		Fingerprint:         query.Get("fingerprint"),
		FastOpen:            cast.ToBool(query.Get("fast-open")),
	}

	return toMap(c)
}

func v2rConf(s string) (map[string]any, error) {
	vmconfig, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed, err: %v", err)
	}
	vmess := Vmess{}
	err = json.Unmarshal(vmconfig, &vmess)
	if err != nil {
		return nil, fmt.Errorf("v2ray config json unmarshal failed, err: %v", err)
	}
	clashVmess := &ClashVmess{}
	clashVmess.Name = vmess.PS

	clashVmess.Type = "vmess"
	clashVmess.Server = vmess.Add
	clashVmess.Udp = true
	switch vmess.Port.(type) {
	case string:
		clashVmess.Port, _ = vmess.Port.(string)
	case int:
		clashVmess.Port, _ = vmess.Port.(int)
	case float64:
		clashVmess.Port, _ = vmess.Port.(float64)
	default:

	}
	clashVmess.UUID = vmess.ID
	clashVmess.AlterID = vmess.Aid
	clashVmess.Cipher = vmess.Type
	clashVmess.ServerName = vmess.Sni
	if strings.EqualFold(vmess.TLS, "tls") {
		clashVmess.TLS = true
	} else {
		clashVmess.TLS = false
	}
	if vmess.Net == "ws" {
		clashVmess.Network = vmess.Net
		clashVmess.WSOpts.Path = vmess.Path
	}

	return toMap(clashVmess)
}

func toMap(obj interface{}) (map[string]any, error) {
	marshal, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("marshal clash vmess failed, err: %v", err)
	}
	clashVmessMap := make(map[string]any)
	err = json.Unmarshal(marshal, &clashVmessMap)
	if err != nil {
		return nil, fmt.Errorf("unmarshal clash vmess failed, err: %v", err)
	}
	return clashVmessMap, nil
}

func ssdConf(ssdJson string) []ClashSS {
	var ssd SSD
	err := json.Unmarshal([]byte(ssdJson), &ssd)
	if err != nil {
		log.Println("ssd json unmarshal err:", err)
		return nil
	}

	var clashSSSlice []ClashSS
	for _, server := range ssd.Servers {
		options, err := url.ParseQuery(server.PluginOptions)
		if err != nil {
			continue
		}

		var ss ClashSS
		ss.Type = "ss"
		ss.Name = server.Remarks
		ss.Cipher = server.Encryption
		ss.Password = server.Password
		ss.Server = server.Server
		ss.Port = server.Port
		ss.Plugin = server.Plugin
		ss.PluginOpts = &PluginOpts{
			Mode: options["obfs"][0],
			Host: options["obfs-host"][0],
		}

		switch {
		case strings.Contains(ss.Plugin, "obfs"):
			ss.Plugin = "obfs"
		}

		clashSSSlice = append(clashSSSlice, ss)
	}

	return clashSSSlice
}

func ssrConf(s string) (map[string]any, error) {
	rawSSRConfig, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	params := strings.Split(string(rawSSRConfig), `:`)

	if len(params) != 6 {
		return nil, fmt.Errorf("ssr config invalid")
	}
	ssr := &ClashRSSR{}
	ssr.Type = "ssr"
	ssr.Server = params[SSRServer]
	ssr.Port = params[SSRPort]
	ssr.Protocol = params[SSRProtocol]
	ssr.Cipher = params[SSRCipher]
	ssr.OBFS = params[SSROBFS]

	// 如果兼容ss协议，就转换为clash的ss配置
	// https://github.com/Dreamacro/clash
	if ssr.Protocol == "origin" && ssr.OBFS == "plain" {
		switch ssr.Cipher {
		case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
			"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
			"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
			"rc4-md5", "chacha20", "chacha20-ietf", "xchacha20",
			"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305":
			ssr.Type = "ss"
		}
	}

	suffix := strings.Split(params[SSRSuffix], "/?")
	if len(suffix) != 2 {
		return nil, fmt.Errorf("ssr config invalid")
	}
	passwordBase64 := suffix[0]
	password, err := base64Decode(passwordBase64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode password failed, err: %v", err)
	}
	ssr.Password = string(password)

	m, err := url.ParseQuery(suffix[1])
	if err != nil {
		return nil, fmt.Errorf("parse ssr suffix failed, err: %v", err)
	}

	for k, v := range m {
		de, err := base64Decode(v[0])
		if err != nil {
			return nil, fmt.Errorf("base64 decode %s failed, err: %v", k, err)
		}
		switch k {
		case "obfsparam":
			ssr.OBFSParam = string(de)
			continue
		case "protoparam":
			ssr.ProtocolParam = string(de)
			continue
		case "remarks":
			ssr.Name = string(de)
			continue
		case "group":
			continue
		}
	}
	return toMap(ssr)
}

func ssConf(s string) (map[string]any, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("error parsing ss URL: %v", err)
	}
	rawSSRConfig, err := base64Decode(u.User.Username())
	if err != nil {
		return nil, fmt.Errorf("error decoding ss URL: %v", err)
	}
	if strings.Contains(string(rawSSRConfig), "@") {
		rawSSRConfig = strings.Replace(rawSSRConfig, "@", ":", 1)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("parse port err: %s", err)
	}

	// 解析 Name
	hashFragment, err := url.PathUnescape(u.Fragment)
	if err != nil {
		return nil, fmt.Errorf("parse hash fragment err: %s", err)
	}
	params := strings.Split(rawSSRConfig, `:`)
	ss := ClashSS{}
	ss.Type = "ss"
	ss.Udp = true
	ss.Cipher = params[0]
	ss.Password = params[1]
	ss.Server = u.Hostname()
	ss.Port = port
	ss.Name = hashFragment
	return toMap(ss)
}

//func ssConf(s string) (map[string]any, error) {
//
//	s, err := url.PathUnescape(s)
//	if err != nil {
//		return nil, fmt.Errorf("url path unescape failed, err: %v", err)
//	}
//
//	findStr := ssReg.FindStringSubmatch(s)
//	if len(findStr) < 4 {
//		return nil, fmt.Errorf("ss config invalid, it should has 4 parts")
//	}
//
//	rawSSRConfig, err := base64Decode(findStr[1])
//	if err != nil {
//		return nil, fmt.Errorf("base64 decode ss config failed, err: %v", err)
//	}
//
//	s = strings.ReplaceAll(s, findStr[1], string(rawSSRConfig))
//	findStr = ssReg2.FindStringSubmatch(s)
//
//	ss := &ClashSS{}
//	ss.Type = "ss"
//	ss.Cipher = findStr[1]
//	ss.Password = findStr[2]
//	ss.Server = findStr[3]
//	ss.Port = findStr[4]
//	ss.Name = findStr[6]
//
//	if findStr[5] != "" && strings.Contains(findStr[5], "plugin") {
//		query := findStr[5][strings.Index(findStr[5], "?")+1:]
//		queryMap, err := url.ParseQuery(query)
//		if err != nil {
//			return nil, fmt.Errorf("parse ss plugin query failed, err: %v", err)
//		}
//
//		ss.Plugin = queryMap["plugin"][0]
//		p := new(PluginOpts)
//		switch {
//		case strings.Contains(ss.Plugin, "obfs"):
//			ss.Plugin = "obfs"
//			p.Mode = queryMap["obfs"][0]
//			if strings.Contains(query, "obfs-host=") {
//				p.Host = queryMap["obfs-host"][0]
//			}
//		case ss.Plugin == "v2ray-plugin":
//			p.Mode = queryMap["mode"][0]
//			if strings.Contains(query, "host=") {
//				p.Host = queryMap["host"][0]
//			}
//			if strings.Contains(query, "path=") {
//				p.Path = queryMap["path"][0]
//			}
//			p.Mux = strings.Contains(query, "mux")
//			p.Tls = strings.Contains(query, "tls")
//			p.SkipCertVerify = true
//		}
//		ss.PluginOpts = p
//	}
//
//	return toMap(ss)
//}

func trojanConf(s string) (map[string]any, error) {
	// 解析 URL
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parse url err: %s", err)
	}

	// 解析查询参数
	queryParams, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("parse query params err: %s", err)
	}

	// 解析端口号
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("parse port err: %s", err)
	}

	// 解析 skip-cert-verify 参数
	skipCertVerify, err := strconv.ParseBool(queryParams.Get("allowInsecure"))
	if err != nil {
		return nil, fmt.Errorf("parse udp err: %s", err)
	}

	// 解析 Name
	hashFragment, err := url.PathUnescape(u.Fragment)
	if err != nil {
		return nil, fmt.Errorf("parse hash fragment err: %s", err)
	}
	p := &Trojan{
		Name:           hashFragment,
		Type:           "trojan",
		Server:         u.Hostname(),
		Port:           port,
		Password:       strings.TrimPrefix(u.User.String(), "trojan:"),
		Udp:            true,
		SkipCertVerify: skipCertVerify,
		Sni:            queryParams.Get("sni"),
	}

	return toMap(p)
}

func base64Decode(s string) (string, error) {
	if i := len(s) % 4; i != 0 {
		s += strings.Repeat("=", 4-i)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("base64 decode failed, err: %v", err)
	}
	return string(b), nil
}
