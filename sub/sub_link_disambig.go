package sub

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/goccy/go-json"
)

// applySubscriptionLinkDisambiguation rewrites vmess ps / URL fragment on each line using the same
// rules as Clash (disambiguateClashProxyName), so plain subscription text matches Clash proxy names.
func applySubscriptionLinkDisambiguation(links []string, tags []string) []string {
	if len(links) == 0 {
		return links
	}
	used := make(map[string]struct{})
	out := make([]string, len(links))
	for i, link := range links {
		link = strings.TrimSpace(link)
		if link == "" {
			out[i] = link
			continue
		}
		tag := ""
		if i < len(tags) {
			tag = tags[i]
		}
		name, ok := subscriptionLinkDisplayName(link)
		if !ok {
			out[i] = link
			continue
		}
		newName := disambiguateClashProxyName(name, tag, used)
		if newName == name {
			out[i] = link
			continue
		}
		out[i] = subscriptionLinkSetDisplayName(link, newName)
	}
	return out
}

func subscriptionLinkDisplayName(link string) (string, bool) {
	switch {
	case strings.HasPrefix(link, "vmess://"):
		raw := strings.TrimPrefix(link, "vmess://")
		data, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			data, err = base64.RawStdEncoding.DecodeString(raw)
			if err != nil {
				return "", false
			}
		}
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			return "", false
		}
		return strings.TrimSpace(fmt.Sprint(obj["ps"])), true
	case strings.HasPrefix(link, "vless://"):
		return urlFragmentDisplayName(link)
	case strings.HasPrefix(link, "trojan://"):
		return urlFragmentDisplayName(link)
	case strings.HasPrefix(link, "ss://"):
		raw := strings.TrimPrefix(link, "ss://")
		fragment := ""
		if idx := strings.Index(raw, "#"); idx >= 0 {
			fragment = raw[idx+1:]
		}
		fragment, _ = url.QueryUnescape(fragment)
		return strings.TrimSpace(fragment), true
	default:
		return "", false
	}
}

func subscriptionLinkSetDisplayName(link, newName string) string {
	switch {
	case strings.HasPrefix(link, "vmess://"):
		raw := strings.TrimPrefix(link, "vmess://")
		data, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			data, err = base64.RawStdEncoding.DecodeString(raw)
			if err != nil {
				return link
			}
		}
		var obj map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			return link
		}
		obj["ps"] = newName
		out, err := json.Marshal(obj)
		if err != nil {
			return link
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(out)
	case strings.HasPrefix(link, "vless://"):
		return urlFragmentSetDisplayName(link, newName)
	case strings.HasPrefix(link, "trojan://"):
		return urlFragmentSetDisplayName(link, newName)
	case strings.HasPrefix(link, "ss://"):
		raw := strings.TrimPrefix(link, "ss://")
		if idx := strings.Index(raw, "#"); idx >= 0 {
			raw = raw[:idx]
		}
		return "ss://" + raw + "#" + url.QueryEscape(newName)
	default:
		return link
	}
}

func urlFragmentDisplayName(link string) (string, bool) {
	u, err := url.Parse(link)
	if err != nil {
		return "", false
	}
	name := strings.TrimPrefix(u.Fragment, "#")
	name, _ = url.QueryUnescape(name)
	return strings.TrimSpace(name), true
}

func urlFragmentSetDisplayName(link, newName string) string {
	u, err := url.Parse(link)
	if err != nil {
		return link
	}
	u.Fragment = newName
	return u.String()
}
