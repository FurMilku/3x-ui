package controller

import (
	"strconv"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"

	"github.com/gin-gonic/gin"
)

// RemotePanelController manages slave panel connections from the master UI.
type RemotePanelController struct {
	BaseController
	svc service.RemotePanelService
}

// NewRemotePanelController registers routes under /panel/api/remotePanels.
func NewRemotePanelController(g *gin.RouterGroup) *RemotePanelController {
	a := &RemotePanelController{}
	g.GET("/list", a.list)
	g.GET("/live/:id", a.live)
	g.POST("/add", a.add)
	g.POST("/update/:id", a.update)
	g.POST("/del/:id", a.del)
	g.POST("/test/:id", a.test)
	g.POST("/sync/:id", a.syncOne)
	g.POST("/syncAll", a.syncAll)
	return a
}

func (a *RemotePanelController) list(c *gin.Context) {
	user := session.GetLoginUser(c)
	list, err := a.svc.ListByUser(user.Id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, list, nil)
}

func (a *RemotePanelController) live(c *gin.Context) {
	user := session.GetLoginUser(c)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	p, err := a.svc.GetByID(user.Id, id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	st := a.svc.FetchLiveStatus(p)
	jsonObj(c, st, nil)
}

func (a *RemotePanelController) add(c *gin.Context) {
	user := session.GetLoginUser(c)
	var p model.RemotePanel
	if err := c.ShouldBindJSON(&p); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}
	if err := a.svc.Create(user.Id, &p); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	p.Password = ""
	jsonMsgObj(c, I18nWeb(c, "success"), p, nil)
}

func (a *RemotePanelController) update(c *gin.Context) {
	user := session.GetLoginUser(c)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	var p model.RemotePanel
	if err := c.ShouldBindJSON(&p); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}
	p.Id = id
	if err := a.svc.Update(user.Id, &p); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	p.Password = ""
	jsonMsgObj(c, I18nWeb(c, "success"), p, nil)
}

func (a *RemotePanelController) del(c *gin.Context) {
	user := session.GetLoginUser(c)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	if err := a.svc.Delete(user.Id, id); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsgObj(c, I18nWeb(c, "pages.inbounds.toasts.inboundDeleteSuccess"), id, nil)
}

func (a *RemotePanelController) test(c *gin.Context) {
	user := session.GetLoginUser(c)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	p, err := a.svc.GetByID(user.Id, id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	if err := a.svc.TestConnection(p); err != nil {
		jsonMsg(c, err.Error(), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "success"), nil)
}

func (a *RemotePanelController) syncOne(c *gin.Context) {
	user := session.GetLoginUser(c)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	if err := service.SyncAllInboundsToPanels(user.Id, []int{id}); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "success"), nil)
}

func (a *RemotePanelController) syncAll(c *gin.Context) {
	user := session.GetLoginUser(c)
	list, err := a.svc.ListByUser(user.Id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	ids := make([]int, 0, len(list))
	for _, p := range list {
		ids = append(ids, p.Id)
	}
	if len(ids) == 0 {
		jsonMsg(c, I18nWeb(c, "noData"), nil)
		return
	}
	if err := service.SyncAllInboundsToPanels(user.Id, ids); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "success"), nil)
}
