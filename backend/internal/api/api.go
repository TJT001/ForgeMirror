package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"

	"forgemirror/backend/internal/auth"
	"forgemirror/backend/internal/config"
	"forgemirror/backend/internal/store"
)

type Server struct {
	cfg   config.Config
	store *store.Store
	auth  *auth.Service
}

func New(cfg config.Config, st *store.Store, authService *auth.Service) *Server {
	return &Server{cfg: cfg, store: st, auth: authService}
}

func (s *Server) Router() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery(), cors())

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	api := router.Group("/api/v1")
	api.POST("/tasks", s.createTask)
	api.GET("/tasks/:id", s.getTask)
	api.GET("/tasks/:id/events", s.taskEvents)
	api.GET("/tasks/:id/artifact", s.taskArtifact)
	api.POST("/tasks/:id/cancel", s.cancelTask)

	api.POST("/auth/devices", s.registerDevice)
	api.POST("/auth/grants", s.createGrant)
	api.GET("/auth/grants/:id", s.getGrantStatus)
	api.POST("/auth/grants/:id/revoke", s.revokeGrant)

	api.POST("/events", s.clientAuth, s.addSecurityEvents)
	api.GET("/events", s.listSecurityEvents)

	worker := api.Group("/worker", s.workerAuth)
	worker.POST("/claim", s.claimTask)
	worker.POST("/tasks/:id/heartbeat", s.heartbeat)
	worker.POST("/tasks/:id/events", s.addEvents)
	worker.POST("/tasks/:id/complete", s.completeTask)

	return router
}

func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers",
			"Content-Type, X-Worker-Token, Last-Event-ID")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func (s *Server) createTask(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, s.cfg.MaxUploadBytes)
	profile := c.DefaultPostForm("profile", "basic")
	signingMode := c.DefaultPostForm("signing_mode", "customer_local")
	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file field required"})
		return
	}

	id := newUUID()
	dir := filepath.Join(s.cfg.DataDir, "uploads", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	target := filepath.Join(dir, "app.apk")
	absolute, err := filepath.Abs(target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := c.SaveUploadedFile(fileHeader, absolute); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	sum, size, err := hashFile(absolute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	task, err := s.store.CreateTask(c.Request.Context(), id, absolute, sum, profile, signingMode)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"task": task, "size": size})
}

func (s *Server) getTask(c *gin.Context) {
	task, err := s.store.GetTask(c.Request.Context(), c.Param("id"))
	if err == pgx.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"task": task})
}

func (s *Server) taskEvents(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	after, _ := strconv.ParseInt(c.Query("after"), 10, 64)
	if after == 0 {
		if last := c.GetHeader("Last-Event-ID"); last != "" {
			after, _ = strconv.ParseInt(last, 10, 64)
		}
	}

	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	for {
		events, err := s.store.ListEvents(ctx, id, after)
		if err != nil {
			writeSSE(c.Writer, "error", fmt.Sprintf(`{"error":%q}`, err.Error()), 0)
			return
		}
		for _, event := range events {
			payload, _ := json.Marshal(event)
			writeSSE(c.Writer, "", string(payload), event.ID)
			after = event.ID
		}
		c.Writer.Flush()

		task, err := s.store.GetTask(ctx, id)
		if err == nil && isTerminal(task.Status) {
			writeSSE(c.Writer, "done", fmt.Sprintf(`{"status":%q}`, task.Status), 0)
			c.Writer.Flush()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func writeSSE(w http.ResponseWriter, event, data string, id int64) {
	if id > 0 {
		fmt.Fprintf(w, "id: %d\n", id)
	}
	if event != "" {
		fmt.Fprintf(w, "event: %s\n", event)
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
}

func isTerminal(status string) bool {
	return status == "succeeded" || status == "failed" || status == "canceled"
}

func (s *Server) taskArtifact(c *gin.Context) {
	task, err := s.store.GetTask(c.Request.Context(), c.Param("id"))
	if err == pgx.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if task.Status != "succeeded" || task.ResultPath == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "artifact not ready", "status": task.Status})
		return
	}
	c.File(*task.ResultPath)
}

func (s *Server) cancelTask(c *gin.Context) {
	task, err := s.store.Cancel(c.Request.Context(), c.Param("id"))
	if err == pgx.ErrNoRows {
		c.JSON(http.StatusConflict, gin.H{"error": "task not cancelable"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"task": task})
}

func (s *Server) registerDevice(c *gin.Context) {
	var request struct {
		DeviceID  string `json:"device_id"`
		PublicKey string `json:"public_key"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || request.DeviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_id and public_key required"})
		return
	}
	publicKey, err := base64.StdEncoding.DecodeString(request.PublicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "public_key must be base64 DER"})
		return
	}
	challenge, err := s.auth.RegisterDevice(c.Request.Context(), request.DeviceID, publicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"device_id":    challenge.DeviceID,
		"challenge_id": challenge.ID,
		"nonce":        base64.StdEncoding.EncodeToString(challenge.Nonce),
		"expires_at":   challenge.ExpiresAt,
	})
}

func (s *Server) createGrant(c *gin.Context) {
	var request struct {
		DeviceID    string `json:"device_id"`
		ChallengeID string `json:"challenge_id"`
		TaskID      string `json:"task_id"`
		Signature   string `json:"signature"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	signature, err := base64.StdEncoding.DecodeString(request.Signature)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "signature must be base64"})
		return
	}
	grant, err := s.auth.CreateGrant(c.Request.Context(), request.DeviceID,
		request.ChallengeID, request.TaskID, signature)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"grant_id":    grant.ID,
		"task_id":     grant.TaskID,
		"expires_at":  grant.ExpiresAt,
		"wrapped_key": base64.StdEncoding.EncodeToString(grant.WrappedKey),
		"algorithm":   "rsa-oaep-sha256",
	})
}

func (s *Server) getGrantStatus(c *gin.Context) {
	grant, err := s.auth.GetGrant(c.Request.Context(), c.Param("id"))
	if err == pgx.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "grant not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"grant_id":   grant.ID,
		"device_id":  grant.DeviceID,
		"task_id":    grant.TaskID,
		"expires_at": grant.ExpiresAt,
		"revoked":    grant.Revoked,
	})
}

func (s *Server) revokeGrant(c *gin.Context) {
	if err := s.auth.RevokeGrant(c.Request.Context(), c.Param("id")); err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "grant not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked": true})
}

func (s *Server) clientAuth(c *gin.Context) {
	if c.GetHeader("X-Client-Token") != s.cfg.ClientToken {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid client token"})
		return
	}
	c.Next()
}

func (s *Server) addSecurityEvents(c *gin.Context) {
	var request struct {
		AppPackage string                   `json:"app_package"`
		DeviceID   string                   `json:"device_id"`
		Events     []store.NewSecurityEvent `json:"events"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || request.AppPackage == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "app_package and events required"})
		return
	}
	if len(request.Events) == 0 || len(request.Events) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "events must contain 1..200 items"})
		return
	}
	for _, event := range request.Events {
		if event.Kind == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "event kind required"})
			return
		}
	}
	var deviceID *string
	if request.DeviceID != "" {
		deviceID = &request.DeviceID
	}
	if err := s.store.AddSecurityEvents(c.Request.Context(), request.AppPackage,
		deviceID, request.Events); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"accepted": len(request.Events)})
}

func (s *Server) listSecurityEvents(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	events, err := s.store.ListSecurityEvents(c.Request.Context(), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events})
}

func (s *Server) workerAuth(c *gin.Context) {
	if c.GetHeader("X-Worker-Token") != s.cfg.WorkerToken {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid worker token"})
		return
	}
	c.Next()
}

func (s *Server) claimTask(c *gin.Context) {
	var request struct {
		WorkerID     string `json:"worker_id"`
		LeaseSeconds int    `json:"lease_seconds"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || request.WorkerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "worker_id required"})
		return
	}
	if request.LeaseSeconds <= 0 {
		request.LeaseSeconds = s.cfg.LeaseSeconds
	}
	task, err := s.store.ClaimTask(c.Request.Context(), request.WorkerID, request.LeaseSeconds)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if task == nil {
		c.Status(http.StatusNoContent)
		return
	}
	c.JSON(http.StatusOK, gin.H{"task": task})
}

func (s *Server) heartbeat(c *gin.Context) {
	var request struct {
		WorkerID     string `json:"worker_id"`
		LeaseSeconds int    `json:"lease_seconds"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || request.WorkerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "worker_id required"})
		return
	}
	if request.LeaseSeconds <= 0 {
		request.LeaseSeconds = s.cfg.LeaseSeconds
	}
	canceled, err := s.store.Heartbeat(c.Request.Context(), c.Param("id"),
		request.WorkerID, request.LeaseSeconds)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"canceled": canceled})
}

func (s *Server) addEvents(c *gin.Context) {
	var request struct {
		Attempt int              `json:"attempt"`
		Events  []store.NewEvent `json:"events"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid events"})
		return
	}
	if err := s.store.AddEvents(c.Request.Context(), c.Param("id"),
		request.Attempt, request.Events); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Server) completeTask(c *gin.Context) {
	var request struct {
		WorkerID    string  `json:"worker_id"`
		Success     bool    `json:"success"`
		ResultPath  *string `json:"result_path"`
		PackageName *string `json:"package_name"`
		VersionCode *int64  `json:"version_code"`
		ReasonCode  *string `json:"reason_code"`
		Message     *string `json:"message"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || request.WorkerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "worker_id required"})
		return
	}
	err := s.store.Complete(c.Request.Context(), c.Param("id"), request.WorkerID,
		request.Success, request.ResultPath, request.PackageName,
		request.VersionCode, request.ReasonCode, request.Message)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hasher := sha256.New()
	size, err := file.WriteTo(hasher)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

func newUUID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		log.Fatalf("uuid: %v", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8],
		value[8:10], value[10:16])
}
