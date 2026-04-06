package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

var remoteSyncMu sync.Mutex

// RemoteSyncAfterInboundChange pushes one inbound to all auto-sync remote panels.
func RemoteSyncAfterInboundChange(userId int, inboundId int) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Warning("remote sync panic:", r)
			}
		}()
		svc := RemotePanelService{}
		if !svc.HasAutoSync(userId) {
			return
		}
		remoteSyncMu.Lock()
		defer remoteSyncMu.Unlock()
		if err := pushInboundToAutoPanels(userId, inboundId); err != nil {
			logger.Warning("remote sync inbound:", err)
		}
	}()
}

// RemoteSyncAfterInboundListChange pushes all inbounds (e.g. new inbound or import).
func RemoteSyncAfterInboundListChange(userId int) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Warning("remote sync panic:", r)
			}
		}()
		svc := RemotePanelService{}
		if !svc.HasAutoSync(userId) {
			return
		}
		remoteSyncMu.Lock()
		defer remoteSyncMu.Unlock()
		if err := syncAllInboundsToAutoPanels(userId); err != nil {
			logger.Warning("remote sync all:", err)
		}
	}()
}

// RemoteSyncInboundDeleted removes an inbound on all auto-sync remotes by tag.
func RemoteSyncInboundDeleted(userId int, tag string) {
	if tag == "" {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Warning("remote sync panic:", r)
			}
		}()
		svc := RemotePanelService{}
		if !svc.HasAutoSync(userId) {
			return
		}
		remoteSyncMu.Lock()
		defer remoteSyncMu.Unlock()
		if err := deleteInboundOnAutoPanels(userId, tag); err != nil {
			logger.Warning("remote sync delete:", err)
		}
	}()
}

func syncAllInboundsToAutoPanels(userId int) error {
	inboundSvc := InboundService{}
	masters, err := inboundSvc.GetInbounds(userId)
	if err != nil {
		return err
	}
	panels, err := listAutoPanels(userId)
	if err != nil {
		return err
	}
	for i := range panels {
		p := panels[i]
		if err := pushAllToPanel(&p, masters); err != nil {
			logger.Warning("remote sync panel", p.Id, err)
		}
	}
	return nil
}

func pushInboundToAutoPanels(userId int, inboundId int) error {
	inboundSvc := InboundService{}
	masters, err := inboundSvc.GetInbounds(userId)
	if err != nil {
		return err
	}
	var master *model.Inbound
	for _, ib := range masters {
		if ib.Id == inboundId {
			master = ib
			break
		}
	}
	if master == nil {
		return nil
	}
	panels, err := listAutoPanels(userId)
	if err != nil {
		return err
	}
	for i := range panels {
		p := panels[i]
		if err := pushAllToPanel(&p, []*model.Inbound{master}); err != nil {
			logger.Warning("remote sync panel", p.Id, err)
		}
	}
	return nil
}

func listAutoPanels(userId int) ([]model.RemotePanel, error) {
	svc := RemotePanelService{}
	all, err := svc.ListByUser(userId)
	if err != nil {
		return nil, err
	}
	var out []model.RemotePanel
	for _, p := range all {
		if p.AutoSync {
			// password was cleared in ListByUser — reload full row for credentials
			full, err := svc.GetByID(userId, p.Id)
			if err != nil {
				continue
			}
			out = append(out, *full)
		}
	}
	return out, nil
}

func pushAllToPanel(panel *model.RemotePanel, masters []*model.Inbound) error {
	cl, err := newRemoteAPIClient(panel.BaseURL, panel.SkipTLSVerify)
	if err != nil {
		return err
	}
	if err := cl.login(panel.Username, panel.Password); err != nil {
		return err
	}
	remoteList, err := cl.getInboundsList()
	if err != nil {
		return err
	}
	remoteByTag := make(map[string]int, len(remoteList))
	for _, r := range remoteList {
		if r != nil && r.Tag != "" {
			remoteByTag[r.Tag] = r.Id
		}
	}
	for _, m := range masters {
		if m == nil {
			continue
		}
		rid, ok := remoteByTag[m.Tag]
		if !ok {
			imp := cloneInboundForImport(m)
			if err := cl.importInbound(imp); err != nil {
				return err
			}
			continue
		}
		var remoteFull *model.Inbound
		for _, r := range remoteList {
			if r != nil && r.Id == rid {
				remoteFull = r
				break
			}
		}
		if remoteFull == nil {
			return fmt.Errorf("remote inbound id %d not in list", rid)
		}
		merged := mergeInboundForRemoteUpdate(m, remoteFull)
		if err := cl.updateInbound(rid, merged); err != nil {
			return err
		}
	}
	return nil
}

func deleteInboundOnAutoPanels(userId int, tag string) error {
	panels, err := listAutoPanels(userId)
	if err != nil {
		return err
	}
	for i := range panels {
		p := &panels[i]
		cl, err := newRemoteAPIClient(p.BaseURL, p.SkipTLSVerify)
		if err != nil {
			logger.Warning(err)
			continue
		}
		if err := cl.login(p.Username, p.Password); err != nil {
			logger.Warning(err)
			continue
		}
		list, err := cl.getInboundsList()
		if err != nil {
			logger.Warning(err)
			continue
		}
		for _, r := range list {
			if r != nil && r.Tag == tag {
				if err := cl.delInbound(r.Id); err != nil {
					logger.Warning("remote delete", err)
				}
				break
			}
		}
	}
	return nil
}

func cloneInboundForImport(src *model.Inbound) *model.Inbound {
	b, _ := json.Marshal(src)
	var dst model.Inbound
	_ = json.Unmarshal(b, &dst)
	dst.Id = 0
	dst.UserId = 0
	dst.Up = 0
	dst.Down = 0
	dst.Total = 0
	dst.AllTime = 0
	for i := range dst.ClientStats {
		dst.ClientStats[i].Id = 0
		dst.ClientStats[i].InboundId = 0
		dst.ClientStats[i].Up = 0
		dst.ClientStats[i].Down = 0
		dst.ClientStats[i].AllTime = 0
		dst.ClientStats[i].LastOnline = 0
	}
	return &dst
}

func mergeInboundForRemoteUpdate(master, remote *model.Inbound) *model.Inbound {
	b, _ := json.Marshal(master)
	var dst model.Inbound
	_ = json.Unmarshal(b, &dst)
	dst.Id = remote.Id
	dst.UserId = remote.UserId
	dst.Up = remote.Up
	dst.Down = remote.Down
	dst.Total = remote.Total
	dst.AllTime = remote.AllTime

	remoteByEmail := make(map[string]xray.ClientTraffic, len(remote.ClientStats))
	for _, ct := range remote.ClientStats {
		remoteByEmail[strings.ToLower(ct.Email)] = ct
	}
	outStats := make([]xray.ClientTraffic, 0, len(master.ClientStats))
	for _, m := range master.ClientStats {
		email := strings.ToLower(m.Email)
		if r, ok := remoteByEmail[email]; ok {
			r.Enable = m.Enable
			r.Total = m.Total
			r.ExpiryTime = m.ExpiryTime
			r.Reset = m.Reset
			outStats = append(outStats, r)
		} else {
			m2 := m
			m2.Id = 0
			m2.InboundId = 0
			m2.Up = 0
			m2.Down = 0
			m2.AllTime = 0
			m2.LastOnline = 0
			outStats = append(outStats, m2)
		}
	}
	dst.ClientStats = outStats
	return &dst
}

// SyncAllInboundsToPanels pushes all master inbounds to the given panel ids (manual sync).
func SyncAllInboundsToPanels(userId int, panelIDs []int) error {
	remoteSyncMu.Lock()
	defer remoteSyncMu.Unlock()
	inboundSvc := InboundService{}
	masters, err := inboundSvc.GetInbounds(userId)
	if err != nil {
		return err
	}
	svc := RemotePanelService{}
	for _, pid := range panelIDs {
		p, err := svc.GetByID(userId, pid)
		if err != nil {
			return err
		}
		if err := pushAllToPanel(p, masters); err != nil {
			return err
		}
	}
	return nil
}
