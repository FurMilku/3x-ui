package sub

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/goccy/go-json"
	"github.com/goccy/go-yaml"

	"github.com/mhsanaei/3x-ui/v2/xray"
)

type clashConverter struct{}

func newClashConverter() *clashConverter {
	return &clashConverter{}
}

func (c *clashConverter) BuildYAML(links []string, clashDisambigTags []string, traffic xray.ClientTraffic, subTitle string, profile string) (string, error) {
	_ = traffic
	proxies := make([]map[string]any, 0, len(links))
	proxyNames := make([]string, 0, len(links))
	usedNames := map[string]struct{}{}
	for i, raw := range links {
		link := strings.TrimSpace(raw)
		tag := ""
		if i < len(clashDisambigTags) {
			tag = clashDisambigTags[i]
		}
		if link == "" {
			continue
		}

		p, err := c.parseProxy(link)
		if err != nil || p == nil {
			continue
		}
		name, _ := p["name"].(string)
		if name == "" {
			name = fmt.Sprintf("node-%d", len(proxies)+1)
		}
		name = disambiguateClashProxyName(name, tag, usedNames)
		p["name"] = name

		proxies = append(proxies, p)
		proxyNames = append(proxyNames, name)
	}

	groupName := strings.TrimSpace(subTitle)
	if groupName == "" {
		groupName = "3x-ui"
	}

	allNames := append([]string{}, proxyNames...)
	autoName := "自动选择"
	fallbackName := "故障转移"

	groups := []map[string]any{
		{
			"name":    groupName,
			"type":    "select",
			"proxies": allNames,
		},
	}
	if strings.ToLower(strings.TrimSpace(profile)) != "compat" {
		groups[0]["proxies"] = append([]string{autoName, fallbackName}, allNames...)
		groups = append(groups,
			map[string]any{
				"name":     autoName,
				"type":     "url-test",
				"url":      "http://www.gstatic.com/generate_204",
				"interval": 86400,
				"proxies":  allNames,
			},
			map[string]any{
				"name":     fallbackName,
				"type":     "fallback",
				"url":      "http://www.gstatic.com/generate_204",
				"interval": 7200,
				"proxies":  allNames,
			},
		)
	}

	dnsCfg := map[string]any{
		"enable":             true,
		"ipv6":               true,
		"default-nameserver": []string{"223.5.5.5", "119.29.29.29"},
		"enhanced-mode":      "fake-ip",
		"fake-ip-range":      "198.18.0.1/16",
		"use-hosts":          true,
		"nameserver":         []string{"https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"},
	}
	if strings.ToLower(strings.TrimSpace(profile)) == "compat" {
		dnsCfg = map[string]any{
			"enable":             true,
			"ipv6":               false,
			"default-nameserver": []string{"223.5.5.5", "119.29.29.29"},
			"enhanced-mode":      "fake-ip",
			"fake-ip-range":      "198.18.0.1/16",
			"use-hosts":          true,
			"nameserver":         []string{"https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"},
		}
	}

	cfg := map[string]any{
		"mixed-port":          7890,
		"allow-lan":           true,
		"bind-address":        "*",
		"find-process-mode":   "strict",
		"mode":                "rule",
		"log-level":           "info",
		"ipv6":                true,
		"external-controller": "127.0.0.1:9090",
		"geox-url": map[string]any{
			"geoip":   "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
			"geosite": "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
			"mmdb":    "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb",
		},
		"profile": map[string]any{
			"store-selected": false,
			"store-fake-ip":  true,
		},
		"dns":                 dnsCfg,
		"proxies":             proxies,
		"proxy-groups":        groups,
		"rules": []string{
			"DOMAIN,injections.adguard.org,DIRECT",
			"DOMAIN,local.adguard.org,DIRECT",
			"DOMAIN-SUFFIX,local,DIRECT",
			"IP-CIDR,127.0.0.0/8,DIRECT",
			"IP-CIDR,10.0.0.0/8,DIRECT",
			"IP-CIDR,172.16.0.0/12,DIRECT",
			"IP-CIDR,192.168.0.0/16,DIRECT",
			"IP-CIDR,100.64.0.0/10,DIRECT",
			"IP-CIDR,224.0.0.0/4,DIRECT",
			"IP-CIDR6,fe80::/10,DIRECT",
			"DOMAIN-SUFFIX,cn,DIRECT",
			"GEOIP,CN,DIRECT",
			"MATCH," + groupName,
		},
	}
	if strings.ToLower(strings.TrimSpace(profile)) == "compat" {
		delete(cfg, "geox-url")
		delete(cfg, "profile")
		cfg["ipv6"] = false
		cfg["find-process-mode"] = "off"
	}

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (c *clashConverter) parseProxy(link string) (map[string]any, error) {
	switch {
	case strings.HasPrefix(link, "vmess://"):
		return c.parseVMess(link)
	case strings.HasPrefix(link, "vless://"):
		return c.parseVLess(link)
	case strings.HasPrefix(link, "trojan://"):
		return c.parseTrojan(link)
	case strings.HasPrefix(link, "ss://"):
		return c.parseShadowsocks(link)
	default:
		return nil, fmt.Errorf("unsupported link")
	}
}

func (c *clashConverter) parseVMess(link string) (map[string]any, error) {
	raw := strings.TrimPrefix(link, "vmess://")
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		data, err = base64.RawStdEncoding.DecodeString(raw)
		if err != nil {
			return nil, err
		}
	}
	obj := map[string]any{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}

	port, _ := strconv.Atoi(fmt.Sprint(obj["port"]))
	name := fmt.Sprint(obj["ps"])
	network := fmt.Sprint(obj["net"])

	proxy := map[string]any{
		"name":    name,
		"type":    "vmess",
		"server":  fmt.Sprint(obj["add"]),
		"port":    port,
		"uuid":    fmt.Sprint(obj["id"]),
		"alterId": 0,
		"cipher":  "auto",
		"udp":     true,
	}

	if scy := strings.TrimSpace(fmt.Sprint(obj["scy"])); scy != "" && scy != "<nil>" {
		proxy["cipher"] = scy
	}
	if network == "httpupgrade" || network == "xhttp" {
		// Clash does not have dedicated httpupgrade/xhttp networks.
		// Map to ws while preserving host/path.
		proxy["network"] = "ws"
	} else if network != "" && network != "tcp" {
		proxy["network"] = network
	}
	if tls := strings.EqualFold(fmt.Sprint(obj["tls"]), "tls"); tls {
		proxy["tls"] = true
	}
	if insecure := strings.TrimSpace(fmt.Sprint(obj["allowInsecure"])); insecure == "1" || strings.EqualFold(insecure, "true") {
		proxy["skip-cert-verify"] = true
	}
	if sni := strings.TrimSpace(fmt.Sprint(obj["sni"])); sni != "" && sni != "<nil>" {
		proxy["servername"] = sni
	}
	if alpn := strings.TrimSpace(fmt.Sprint(obj["alpn"])); alpn != "" && alpn != "<nil>" {
		proxy["alpn"] = splitCSV(alpn)
	}
	if fp := strings.TrimSpace(fmt.Sprint(obj["fp"])); fp != "" && fp != "<nil>" {
		proxy["client-fingerprint"] = fp
	}
	if network == "ws" || network == "httpupgrade" || network == "xhttp" {
		opts := map[string]any{}
		if p := strings.TrimSpace(fmt.Sprint(obj["path"])); p != "" && p != "<nil>" {
			opts["path"] = p
		}
		if h := strings.TrimSpace(fmt.Sprint(obj["host"])); h != "" && h != "<nil>" {
			opts["headers"] = map[string]any{"Host": h}
		}
		if len(opts) > 0 {
			proxy["ws-opts"] = opts
		}
	}
	if network == "grpc" {
		opts := map[string]any{}
		if p := strings.TrimSpace(fmt.Sprint(obj["path"])); p != "" && p != "<nil>" {
			opts["grpc-service-name"] = p
		}
		if auth := strings.TrimSpace(fmt.Sprint(obj["authority"])); auth != "" && auth != "<nil>" {
			opts["grpc-authority"] = auth
		}
		if len(opts) > 0 {
			proxy["grpc-opts"] = opts
		}
	}

	return proxy, nil
}

func (c *clashConverter) parseVLess(link string) (map[string]any, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(u.Port())
	q := u.Query()
	name := strings.TrimPrefix(u.Fragment, "#")
	name, _ = url.QueryUnescape(name)

	proxy := map[string]any{
		"name":   name,
		"type":   "vless",
		"server": u.Hostname(),
		"port":   port,
		"uuid":   u.User.Username(),
		"udp":    true,
	}

	if netw := q.Get("type"); netw != "" {
		proxy["network"] = netw
	}
	if sec := q.Get("security"); sec == "tls" || sec == "reality" {
		proxy["tls"] = true
	}
	if insecure := strings.TrimSpace(q.Get("allowInsecure")); insecure == "1" || strings.EqualFold(insecure, "true") {
		proxy["skip-cert-verify"] = true
	}
	if sni := q.Get("sni"); sni != "" {
		proxy["servername"] = sni
	}
	if alpn := strings.TrimSpace(q.Get("alpn")); alpn != "" {
		proxy["alpn"] = splitCSV(alpn)
	}
	if fp := strings.TrimSpace(q.Get("fp")); fp != "" {
		proxy["client-fingerprint"] = fp
	}
	if flow := q.Get("flow"); flow != "" {
		proxy["flow"] = flow
	}
	if netw := q.Get("type"); netw == "ws" {
		opts := map[string]any{}
		if p := q.Get("path"); p != "" {
			opts["path"] = p
		}
		if h := q.Get("host"); h != "" {
			opts["headers"] = map[string]any{"Host": h}
		}
		if len(opts) > 0 {
			proxy["ws-opts"] = opts
		}
	}
	if netw := q.Get("type"); netw == "httpupgrade" || netw == "xhttp" {
		// Clash does not have dedicated httpupgrade/xhttp networks.
		// Map to ws-opts so clients can still use the subscription.
		proxy["network"] = "ws"
		opts := map[string]any{}
		if p := q.Get("path"); p != "" {
			opts["path"] = p
		}
		if h := q.Get("host"); h != "" {
			opts["headers"] = map[string]any{"Host": h}
		}
		if len(opts) > 0 {
			proxy["ws-opts"] = opts
		}
	}
	if netw := q.Get("type"); netw == "grpc" {
		opts := map[string]any{}
		if p := q.Get("serviceName"); p != "" {
			opts["grpc-service-name"] = p
		}
		if auth := q.Get("authority"); auth != "" {
			opts["grpc-authority"] = auth
		}
		if len(opts) > 0 {
			proxy["grpc-opts"] = opts
		}
	}
	if q.Get("security") == "reality" {
		ro := map[string]any{}
		if pbk := q.Get("pbk"); pbk != "" {
			ro["public-key"] = pbk
		}
		if sid := q.Get("sid"); sid != "" {
			ro["short-id"] = sid
		}
		if pqv := q.Get("pqv"); pqv != "" {
			ro["mldsa65-verify"] = pqv
		}
		if len(ro) > 0 {
			proxy["reality-opts"] = ro
		}
		if fp := q.Get("fp"); fp != "" {
			proxy["client-fingerprint"] = fp
		}
	}

	return proxy, nil
}

func (c *clashConverter) parseTrojan(link string) (map[string]any, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(u.Port())
	q := u.Query()
	name := strings.TrimPrefix(u.Fragment, "#")
	name, _ = url.QueryUnescape(name)

	proxy := map[string]any{
		"name":     name,
		"type":     "trojan",
		"server":   u.Hostname(),
		"port":     port,
		"password": u.User.Username(),
		"udp":      true,
	}
	if netw := q.Get("type"); netw != "" && netw != "tcp" {
		proxy["network"] = netw
	}
	if sec := q.Get("security"); sec == "tls" || sec == "reality" {
		proxy["tls"] = true
	}
	if insecure := strings.TrimSpace(q.Get("allowInsecure")); insecure == "1" || strings.EqualFold(insecure, "true") {
		proxy["skip-cert-verify"] = true
	}
	if sni := q.Get("sni"); sni != "" {
		proxy["sni"] = sni
	}
	if alpn := strings.TrimSpace(q.Get("alpn")); alpn != "" {
		proxy["alpn"] = splitCSV(alpn)
	}
	if fp := strings.TrimSpace(q.Get("fp")); fp != "" {
		proxy["client-fingerprint"] = fp
	}
	if netw := q.Get("type"); netw == "ws" {
		opts := map[string]any{}
		if p := q.Get("path"); p != "" {
			opts["path"] = p
		}
		if h := q.Get("host"); h != "" {
			opts["headers"] = map[string]any{"Host": h}
		}
		if len(opts) > 0 {
			proxy["ws-opts"] = opts
		}
	}
	if netw := q.Get("type"); netw == "httpupgrade" || netw == "xhttp" {
		proxy["network"] = "ws"
		opts := map[string]any{}
		if p := q.Get("path"); p != "" {
			opts["path"] = p
		}
		if h := q.Get("host"); h != "" {
			opts["headers"] = map[string]any{"Host": h}
		}
		if len(opts) > 0 {
			proxy["ws-opts"] = opts
		}
	}
	if netw := q.Get("type"); netw == "grpc" {
		opts := map[string]any{}
		if p := q.Get("serviceName"); p != "" {
			opts["grpc-service-name"] = p
		}
		if auth := q.Get("authority"); auth != "" {
			opts["grpc-authority"] = auth
		}
		if len(opts) > 0 {
			proxy["grpc-opts"] = opts
		}
	}
	return proxy, nil
}

func (c *clashConverter) parseShadowsocks(link string) (map[string]any, error) {
	raw := strings.TrimPrefix(link, "ss://")
	queryPart := ""

	fragment := ""
	if idx := strings.Index(raw, "#"); idx >= 0 {
		fragment = raw[idx+1:]
		raw = raw[:idx]
	}
	fragment, _ = url.QueryUnescape(fragment)

	if qIdx := strings.Index(raw, "?"); qIdx >= 0 {
		queryPart = raw[qIdx+1:]
		raw = raw[:qIdx]
	}

	var userInfoPart string
	var hostPortPart string
	if at := strings.LastIndex(raw, "@"); at > 0 {
		userInfoPart = raw[:at]
		hostPortPart = raw[at+1:]
	} else {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(raw)
			if err != nil {
				return nil, err
			}
		}
		parts := strings.SplitN(string(decoded), "@", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid ss link")
		}
		userInfoPart = parts[0]
		hostPortPart = parts[1]
	}

	decodedUserInfo, err := base64.StdEncoding.DecodeString(userInfoPart)
	if err != nil {
		decodedUserInfo, err = base64.RawStdEncoding.DecodeString(userInfoPart)
		if err != nil {
			decodedUserInfo = []byte(userInfoPart)
		}
	}

	authParts := strings.SplitN(string(decodedUserInfo), ":", 2)
	if len(authParts) != 2 {
		return nil, fmt.Errorf("invalid ss auth")
	}
	method := authParts[0]
	password := authParts[1]

	hostPort, err := url.Parse("http://" + hostPortPart)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(hostPort.Port())

	proxy := map[string]any{
		"name":     fragment,
		"type":     "ss",
		"server":   hostPort.Hostname(),
		"port":     port,
		"cipher":   method,
		"password": password,
		"udp":      true,
	}

	if queryPart != "" {
		q, _ := url.ParseQuery(queryPart)
		if plugin := strings.TrimSpace(q.Get("plugin")); plugin != "" {
			pluginType, pluginOpts := parseSSPlugin(plugin)
			if pluginType != "" {
				proxy["plugin"] = pluginType
			}
			if len(pluginOpts) > 0 {
				proxy["plugin-opts"] = pluginOpts
			}
		}
		if insecure := strings.TrimSpace(q.Get("allowInsecure")); insecure == "1" || strings.EqualFold(insecure, "true") {
			proxy["skip-cert-verify"] = true
		}
		if fp := strings.TrimSpace(q.Get("fp")); fp != "" {
			proxy["client-fingerprint"] = fp
		}
	}

	return proxy, nil
}

func clashSanitizeTag(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.TrimSpace(s)
}

// disambiguateClashProxyName assigns a unique Clash proxy name. When clashTag is non-empty (e.g. remote panel remark),
// duplicate base names use "base-tag" instead of "base-2", "base-3".
func disambiguateClashProxyName(name string, clashTag string, used map[string]struct{}) string {
	base := strings.TrimSpace(name)
	if base == "" {
		base = "node"
	}
	if _, taken := used[base]; !taken {
		used[base] = struct{}{}
		return base
	}
	tag := clashSanitizeTag(clashTag)
	if tag != "" {
		candidate := base + "-" + tag
		if _, taken := used[candidate]; !taken {
			used[candidate] = struct{}{}
			return candidate
		}
		for i := 2; ; i++ {
			alt := fmt.Sprintf("%s-%s-%d", base, tag, i)
			if _, taken := used[alt]; !taken {
				used[alt] = struct{}{}
				return alt
			}
		}
	}
	for i := 2; ; i++ {
		alt := fmt.Sprintf("%s-%d", base, i)
		if _, taken := used[alt]; !taken {
			used[alt] = struct{}{}
			return alt
		}
	}
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseSSPlugin(raw string) (string, map[string]any) {
	plugin := strings.TrimSpace(raw)
	if plugin == "" {
		return "", nil
	}
	parts := strings.Split(plugin, ";")
	pluginName := strings.ToLower(strings.TrimSpace(parts[0]))
	opts := map[string]any{}

	// Common plugin name aliases in SS share links.
	switch pluginName {
	case "obfs-local", "simple-obfs":
		pluginName = "obfs"
	case "v2ray-plugin":
		pluginName = "v2ray-plugin"
	}

	for _, token := range parts[1:] {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.Contains(token, "=") {
			kv := strings.SplitN(token, "=", 2)
			k := strings.TrimSpace(kv[0])
			v := strings.TrimSpace(kv[1])
			switch k {
			case "obfs", "mode":
				opts["mode"] = v
			case "obfs-host", "host":
				opts["host"] = v
			case "path":
				opts["path"] = v
			case "tls":
				opts["tls"] = (v == "1" || strings.EqualFold(v, "true"))
			default:
				opts[k] = v
			}
		} else if token == "tls" {
			opts["tls"] = true
		}
	}

	if len(opts) == 0 {
		return pluginName, nil
	}
	return pluginName, opts
}
