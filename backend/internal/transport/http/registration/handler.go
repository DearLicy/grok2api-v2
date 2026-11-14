package registration

import (
	"net/http"
	"strings"

	registrationapp "github.com/chenyme/grok2api/backend/internal/application/registration"
	registrationinfra "github.com/chenyme/grok2api/backend/internal/infra/registration"
	"github.com/chenyme/grok2api/backend/internal/shared/response"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	manager *registrationinfra.Manager
	service *registrationapp.Service
}

func NewHandler(manager *registrationinfra.Manager, service *registrationapp.Service) *Handler {
	return &Handler{manager: manager, service: service}
}

// RegisterAdmin exposes a narrow proxy surface. The SPA talks to the same Go
// origin; the Python worker port is never published.
func (h *Handler) RegisterAdmin(router *gin.RouterGroup) {
	router.GET("/registration/status", h.status)
	router.GET("/registration/config", h.proxyFunc("/config"))
	router.PUT("/registration/config", h.proxyFunc("/config"))
	router.GET("/registration/browsers", h.proxyFunc("/browsers"))
	router.GET("/registration/accounts", h.proxyFunc("/accounts"))
	router.GET("/registration/accounts/export", h.proxyFunc("/accounts/export"))
	router.POST("/registration/accounts/import", h.proxyFunc("/accounts/import"))
	router.POST("/registration/accounts/delete", h.proxyFunc("/accounts/delete"))
	router.GET("/registration/tasks", h.proxyFunc("/tasks"))
	router.GET("/registration/tasks/latest", h.proxyFunc("/tasks/latest"))
	router.POST("/registration/tasks", h.proxyFunc("/tasks"))
	router.GET("/registration/tasks/:id", h.proxyTask())
	router.GET("/registration/tasks/:id/logs", h.proxyTaskLogs())
	router.POST("/registration/tasks/:id/cancel", h.proxyTaskCancel())
}

func (h *Handler) RegisterInternal(router *gin.RouterGroup) {
	router.GET("/registration/accounts/exists", h.exists)
	router.POST("/registration/accounts/ingest", h.ingest)
}

func (h *Handler) status(c *gin.Context) {
	data := map[string]any{}
	for key, value := range h.manager.Status() {
		data[key] = value
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

func (h *Handler) proxyFunc(path string) gin.HandlerFunc {
	return func(c *gin.Context) {
		h.manager.Proxy(c.Writer, c.Request, path)
	}
}

func (h *Handler) proxyTask() gin.HandlerFunc {
	return func(c *gin.Context) {
		h.manager.Proxy(c.Writer, c.Request, "/tasks/"+c.Param("id"))
	}
}

func (h *Handler) proxyTaskLogs() gin.HandlerFunc {
	return func(c *gin.Context) {
		h.manager.Proxy(c.Writer, c.Request, "/tasks/"+c.Param("id")+"/logs")
	}
}

func (h *Handler) proxyTaskCancel() gin.HandlerFunc {
	return func(c *gin.Context) {
		h.manager.Proxy(c.Writer, c.Request, "/tasks/"+c.Param("id")+"/cancel")
	}
}

func (h *Handler) exists(c *gin.Context) {
	email := strings.TrimSpace(c.Query("email"))
	if email == "" {
		response.Error(c, http.StatusBadRequest, "invalidEmail", "缺少邮箱")
		return
	}
	result, err := h.service.Exists(c.Request.Context(), email)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "registrationLookupFailed", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}

func (h *Handler) ingest(c *gin.Context) {
	var payload registrationapp.IngestInput
	if err := c.ShouldBindJSON(&payload); err != nil {
		response.Error(c, http.StatusBadRequest, "invalidRegistrationCredential", "注册账号凭据格式无效")
		return
	}
	result, err := h.service.Ingest(c.Request.Context(), payload)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "registrationIngestFailed", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}
