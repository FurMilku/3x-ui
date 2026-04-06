package sub

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

const mergeUserAgent = "3x-ui-subscription-merge/1.0"

// mergeRemoteSubscriptionLines merges manual URLs (settings), then slave panels flagged MergeSub, after local lines.
func (s *SubService) mergeRemoteSubscriptionLines(subId string, local []string, userId int) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(local)+16)
	for _, line := range local {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}

	raw, _ := s.settingService.GetSubMergeURLs()
	for _, row := range strings.Split(raw, "\n") {
		row = strings.TrimSpace(row)
		if row == "" || strings.HasPrefix(row, "#") {
			continue
		}
		fetchURL := replaceSubIDPlaceholder(row, subId)
		remote, err := fetchSubscriptionLines(fetchURL)
		if err != nil {
			logger.Warning("SubService merge: fetch failed:", fetchURL, err)
			continue
		}
		out = appendUniqueMergeLines(seen, out, remote)
	}

	if userId > 0 {
		out = s.appendMergedFromRemotePanels(userId, subId, seen, out)
	}
	return out
}

func appendUniqueMergeLines(seen map[string]struct{}, out []string, remote []string) []string {
	for _, r := range remote {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}

func (s *SubService) appendMergedFromRemotePanels(userId int, subId string, seen map[string]struct{}, out []string) []string {
	db := database.GetDB()
	var panels []model.RemotePanel
	err := db.Where("user_id = ? AND merge_sub = ?", userId, true).Order("sort asc, id asc").Find(&panels).Error
	if err != nil || len(panels) == 0 {
		return out
	}
	for i := range panels {
		p := &panels[i]
		u := remotePanelSubscriptionURL(p, subId)
		if u == "" {
			continue
		}
		remote, err := fetchSubscriptionLinesTLS(u, p.SkipTLSVerify)
		if err != nil {
			logger.Warning("SubService merge remote panel:", p.Id, u, err)
			continue
		}
		out = appendUniqueMergeLines(seen, out, remote)
	}
	return out
}

func remotePanelSubscriptionURL(p *model.RemotePanel, subId string) string {
	if p == nil || subId == "" {
		return ""
	}
	base := strings.TrimSpace(p.SubPublicBase)
	if base != "" {
		return strings.TrimRight(base, "/") + "/" + subId
	}
	b := strings.TrimRight(strings.TrimSpace(p.BaseURL), "/")
	if b == "" {
		return ""
	}
	return b + "/sub/" + subId
}

func replaceSubIDPlaceholder(tpl, subId string) string {
	s := strings.ReplaceAll(tpl, "{subid}", subId)
	s = strings.ReplaceAll(s, "{SUBID}", subId)
	return s
}

func fetchSubscriptionLines(rawURL string) ([]string, error) {
	return fetchSubscriptionLinesTLS(rawURL, false)
}

func fetchSubscriptionLinesTLS(rawURL string, skipTLSVerify bool) ([]string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("merge: invalid subscription URL")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipTLSVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}
	client := &http.Client{
		Timeout:   25 * time.Second,
		Transport: tr,
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", mergeUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("merge: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	return parseSubscriptionBody(body), nil
}

func parseSubscriptionBody(body []byte) []string {
	text := strings.TrimSpace(string(body))
	text = strings.TrimPrefix(text, "\ufeff")
	if text == "" {
		return nil
	}

	// Whole body may be base64 (encrypted subscription mode on remote).
	if lines := tryParseAsBase64Subscription(text); len(lines) > 0 {
		return lines
	}
	return splitNonEmptyLines(text)
}

func tryParseAsBase64Subscription(text string) []string {
	clean := strings.ReplaceAll(strings.ReplaceAll(text, "\n", ""), "\r", "")
	dec, err := base64.StdEncoding.DecodeString(clean)
	if err != nil || len(dec) == 0 {
		return nil
	}
	s := string(dec)
	if !looksLikeShareLinks(s) {
		return nil
	}
	return splitNonEmptyLines(s)
}

func looksLikeShareLinks(s string) bool {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "vmess:") || strings.HasPrefix(s, "vless:") || strings.HasPrefix(s, "trojan:") || strings.HasPrefix(s, "ss://") {
		return true
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		return strings.HasPrefix(line, "vmess:") || strings.HasPrefix(line, "vless:") || strings.HasPrefix(line, "trojan:") || strings.HasPrefix(line, "ss://")
	}
	return false
}

func splitNonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" { // skip empty lines
			continue
		}
		out = append(out, line)
	}
	return out
}
