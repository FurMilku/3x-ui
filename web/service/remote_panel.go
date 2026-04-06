package service

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// RemotePanelService manages stored slave panel connections.
type RemotePanelService struct{}

type apiEnvelope struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

// RemotePanelStatus is live data fetched from a slave panel (subset of server.Status).
type RemotePanelStatus struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	NetUp    uint64 `json:"netUp"`    // bytes/s style snapshot (NetIO.Up)
	NetDown  uint64 `json:"netDown"`  // NetIO.Down
	UsedUp   uint64 `json:"usedUp"`   // sum of inbound up (from list) — optional
	UsedDown uint64 `json:"usedDown"` // sum of inbound down
	Xray     string `json:"xray"`     // running state string
}

// ListByUser returns remote panels for a user (passwords cleared).
func (s *RemotePanelService) ListByUser(userId int) ([]model.RemotePanel, error) {
	db := database.GetDB()
	var list []model.RemotePanel
	err := db.Where("user_id = ?", userId).Order("sort asc, id asc").Find(&list).Error
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].Password != "" {
			list[i].Password = ""
		}
	}
	return list, nil
}

// GetByID returns one panel if owned by user.
func (s *RemotePanelService) GetByID(userId int, id int) (*model.RemotePanel, error) {
	db := database.GetDB()
	var p model.RemotePanel
	err := db.Where("id = ? AND user_id = ?", id, userId).First(&p).Error
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Create adds a remote panel row.
func (s *RemotePanelService) Create(userId int, p *model.RemotePanel) error {
	p.Id = 0
	p.UserId = userId
	p.Username = strings.TrimSpace(p.Username)
	p.Password = strings.TrimSpace(p.Password)
	if p.BaseURL == "" || p.Username == "" || p.Password == "" {
		return fmt.Errorf("baseUrl, slave username and password are required")
	}
	p.BaseURL = normalizeBaseURL(p.BaseURL)
	p.SubPublicBase = strings.TrimSpace(p.SubPublicBase)
	return database.GetDB().Create(p).Error
}

// Update modifies a remote panel; empty password keeps the previous value.
func (s *RemotePanelService) Update(userId int, p *model.RemotePanel) error {
	if p.Id <= 0 {
		return fmt.Errorf("invalid id")
	}
	db := database.GetDB()
	var old model.RemotePanel
	err := db.Where("id = ? AND user_id = ?", p.Id, userId).First(&old).Error
	if err != nil {
		return err
	}
	p.UserId = userId
	p.BaseURL = normalizeBaseURL(p.BaseURL)
	p.SubPublicBase = strings.TrimSpace(p.SubPublicBase)
	p.Username = strings.TrimSpace(p.Username)
	if p.Username == "" {
		p.Username = old.Username
	}
	if strings.TrimSpace(p.Password) == "" {
		p.Password = old.Password
	} else {
		p.Password = strings.TrimSpace(p.Password)
	}
	return db.Save(p).Error
}

// Delete removes a remote panel row.
func (s *RemotePanelService) Delete(userId int, id int) error {
	return database.GetDB().Where("id = ? AND user_id = ?", id, userId).Delete(&model.RemotePanel{}).Error
}

// HasAutoSync returns whether any remote panel has auto-sync enabled for this user.
func (s *RemotePanelService) HasAutoSync(userId int) bool {
	db := database.GetDB()
	var n int64
	db.Model(&model.RemotePanel{}).Where("user_id = ? AND auto_sync = ?", userId, true).Count(&n)
	return n > 0
}

func normalizeBaseURL(raw string) string {
	u := strings.TrimSpace(raw)
	u = strings.TrimRight(u, "/")
	if u == "" {
		return ""
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "https://" + u
	}
	return u
}

// --- HTTP client for remote 3x-ui API (session cookie) ---

type remoteAPIClient struct {
	baseURL       string
	skipTLSVerify bool
	httpClient    *http.Client
}

func newRemoteAPIClient(baseURL string, skipTLSVerify bool) (*remoteAPIClient, error) {
	baseURL = normalizeBaseURL(baseURL)
	if baseURL == "" {
		return nil, fmt.Errorf("empty base url")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipTLSVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}
	return &remoteAPIClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Jar:       jar,
			Transport: tr,
			Timeout:   45 * time.Second,
		},
	}, nil
}

func (c *remoteAPIClient) absURL(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return c.baseURL + path
}

func (c *remoteAPIClient) postForm(path string, vals url.Values) (*apiEnvelope, error) {
	req, err := http.NewRequest(http.MethodPost, c.absURL(path), strings.NewReader(vals.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.doAPI(req)
}

func (c *remoteAPIClient) postJSON(path string, body any) (*apiEnvelope, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, c.absURL(path), bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doAPI(req)
}

func (c *remoteAPIClient) get(path string) (*apiEnvelope, error) {
	req, err := http.NewRequest(http.MethodGet, c.absURL(path), nil)
	if err != nil {
		return nil, err
	}
	return c.doAPI(req)
}

func (c *remoteAPIClient) doAPI(req *http.Request) (*apiEnvelope, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var env apiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("invalid json: %w body=%s", err, truncate(string(raw), 200))
	}
	return &env, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func (c *remoteAPIClient) login(username, password string) error {
	v := url.Values{}
	v.Set("username", username)
	v.Set("password", password)
	env, err := c.postForm("/login", v)
	if err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("login failed: %s", env.Msg)
	}
	return nil
}

func (c *remoteAPIClient) getInboundsList() ([]*model.Inbound, error) {
	env, err := c.get("/panel/api/inbounds/list")
	if err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("list inbounds: %s", env.Msg)
	}
	var list []*model.Inbound
	if err := json.Unmarshal(env.Obj, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (c *remoteAPIClient) getInbound(id int) (*model.Inbound, error) {
	env, err := c.get(fmt.Sprintf("/panel/api/inbounds/get/%d", id))
	if err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("get inbound: %s", env.Msg)
	}
	var ib model.Inbound
	if err := json.Unmarshal(env.Obj, &ib); err != nil {
		return nil, err
	}
	return &ib, nil
}

func (c *remoteAPIClient) importInbound(payload *model.Inbound) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	v := url.Values{}
	v.Set("data", string(data))
	env, err := c.postForm("/panel/api/inbounds/import", v)
	if err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("import inbound: %s", env.Msg)
	}
	return nil
}

func (c *remoteAPIClient) updateInbound(id int, payload *model.Inbound) error {
	env, err := c.postJSON(fmt.Sprintf("/panel/api/inbounds/update/%d", id), payload)
	if err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("update inbound: %s", env.Msg)
	}
	return nil
}

func (c *remoteAPIClient) delInbound(id int) error {
	req, err := http.NewRequest(http.MethodPost, c.absURL(fmt.Sprintf("/panel/api/inbounds/del/%d", id)), nil)
	if err != nil {
		return err
	}
	env, err := c.doAPI(req)
	if err != nil {
		return err
	}
	if !env.Success {
		return fmt.Errorf("delete inbound: %s", env.Msg)
	}
	return nil
}

func (c *remoteAPIClient) serverStatus() (*Status, error) {
	env, err := c.get("/panel/api/server/status")
	if err != nil {
		return nil, err
	}
	if !env.Success {
		return nil, fmt.Errorf("status: %s", env.Msg)
	}
	var st Status
	if err := json.Unmarshal(env.Obj, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// FetchLiveStatus logs in and returns traffic + net speeds from the slave.
func (s *RemotePanelService) FetchLiveStatus(p *model.RemotePanel) RemotePanelStatus {
	out := RemotePanelStatus{OK: false}
	if p == nil {
		out.Error = "nil panel"
		return out
	}
	cl, err := newRemoteAPIClient(p.BaseURL, p.SkipTLSVerify)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if err := cl.login(p.Username, p.Password); err != nil {
		out.Error = err.Error()
		return out
	}
	st, err := cl.serverStatus()
	if err != nil {
		out.Error = err.Error()
		return out
	}
	list, err := cl.getInboundsList()
	if err != nil {
		out.Error = err.Error()
		return out
	}
	var uu, dd int64
	for _, ib := range list {
		uu += ib.Up
		dd += ib.Down
	}
	out.OK = true
	out.NetUp = st.NetIO.Up
	out.NetDown = st.NetIO.Down
	out.UsedUp = uint64(uu)
	out.UsedDown = uint64(dd)
	out.Xray = fmt.Sprintf("%v", st.Xray.State)
	return out
}

// TestConnection tries login only.
func (s *RemotePanelService) TestConnection(p *model.RemotePanel) error {
	cl, err := newRemoteAPIClient(p.BaseURL, p.SkipTLSVerify)
	if err != nil {
		return err
	}
	return cl.login(p.Username, p.Password)
}
