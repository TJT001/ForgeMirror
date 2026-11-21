package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

	api.GET("/config", s.clientAuth, s.getClientConfig)
	api.POST("/config", s.clientAuth, s.setClientConfig)
	api.POST("/rules", s.clientAuth, s.publishRulePackage)
	api.GET("/rules/latest", s.clientAuth, s.latestRulePackage)

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
			"Content-Type, X-Worker-Token, X-Client-Token, Last-Event-ID")
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
	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "multipart form required"})
		return
	}
	profile := formValue(form, "profile", "basic")
	signingMode := formValue(form, "signing_mode", "customer_local")
	if !contains([]string{"basic", "enhanced", "financial"}, profile) ||
		!contains([]string{"hsm", "customer_local"}, signingMode) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid profile or signing_mode"})
		return
	}

	files := form.File["file"]
	if len(files) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file field required"})
		return
	}
	fileHeader := files[0]
	sourceExt := strings.ToLower(filepath.Ext(fileHeader.Filename))
	if sourceExt != ".apk" && sourceExt != ".aab" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only .apk or .aab input is supported"})
		return
	}
	aabMode := formValue(form, "aab_mode", "universal")
	if aabMode != "universal" && aabMode != "split" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "aab_mode must be universal or split"})
		return
	}
	if sourceExt != ".aab" && aabMode != "universal" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "split mode requires .aab input"})
		return
	}
	if sourceExt == ".aab" && aabMode == "split" && len(form.File["device_specs"]) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "split mode requires at least one device spec"})
		return
	}
	if sourceExt == ".aab" && len(form.File["splits"]) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "splits cannot be combined with .aab input"})
		return
	}
	if sourceExt != ".aab" && len(form.File["device_specs"]) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device specs require .aab input"})
		return
	}
	if aabMode != "split" && len(form.File["device_specs"]) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device specs require split mode"})
		return
	}

	boolOption := func(name string, fallback bool) (bool, error) {
		value := formValue(form, name, "")
		if value == "" {
			return fallback, nil
		}
		return strconv.ParseBool(value)
	}
	options := map[string]any{
		"auth_url":       formValue(form, "auth_url", ""),
		"event_url":      formValue(form, "event_url", ""),
		"event_token":    formValue(form, "event_token", ""),
		"in_memory_libs": formValue(form, "in_memory_libs", ""),
		"alg":            formValue(form, "alg", "ecdsa-p256-sha256"),
		"shell_version":  formValue(form, "shell_version", "0.1.0"),
		"response":       formValue(form, "response", "toast"),
		"aab_mode":       aabMode,
	}
	for name, fallback := range map[string]bool{
		"no_key_asset":          false,
		"self_decrypt_core":     true,
		"decoy_dynamic":         true,
		"corrupt_section_names": true,
		"self_decrypt_text":     true,
		"detection":             true,
		"whitebox":              true,
	} {
		value, err := boolOption(name, fallback)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid " + name})
			return
		}
		options[name] = value
	}
	maxNative := formValue(form, "max_native_file_mb", "128")
	parsedMax, err := strconv.Atoi(maxNative)
	if err != nil || parsedMax < 1 || parsedMax > 4096 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "max_native_file_mb must be 1..4096"})
		return
	}
	options["max_native_file_mb"] = parsedMax
	if !contains([]string{"log", "toast", "degrade", "block"}, options["response"].(string)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid response mode"})
		return
	}
	if !contains([]string{"ecdsa-p256-sha256", "ed25519"}, options["alg"].(string)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid alg"})
		return
	}

	id := newUUID()
	dir := filepath.Join(s.cfg.DataDir, "uploads", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	target := filepath.Join(dir, "source"+sourceExt)
	absolute, err := filepath.Abs(target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := c.SaveUploadedFile(fileHeader, absolute); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	splits, err := saveUploads(form.File["splits"], filepath.Join(dir, "splits"), ".apk")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	specs, err := saveUploads(form.File["device_specs"], filepath.Join(dir, "device_specs"), ".json")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(splits) > 0 {
		options["splits"] = splits
	}
	if len(specs) > 0 {
		for _, spec := range specs {
			body, readErr := os.ReadFile(spec)
			if readErr != nil || !json.Valid(body) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "device spec must be valid JSON"})
				return
			}
		}
		options["device_specs"] = specs
	}
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	sum, size, err := hashFile(absolute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	task, err := s.store.CreateTask(c.Request.Context(), id, absolute, sum,
		profile, signingMode, optionsJSON)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"task": task, "size": size})
}

func formValue(form *multipart.Form, name, fallback string) string {
	if values := form.Value[name]; len(values) > 0 {
		value := strings.TrimSpace(values[0])
		if value != "" {
			return value
		}
	}
	return fallback
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func saveUploads(files []*multipart.FileHeader, dir, extension string) ([]string, error) {
	var paths []string
	if len(files) == 0 {
		return paths, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	for index, header := range files {
		if strings.ToLower(filepath.Ext(header.Filename)) != extension {
			return nil, fmt.Errorf("%s is not %s", header.Filename, extension)
		}
		name := fmt.Sprintf("%02d_%s", index, filepath.Base(header.Filename))
		target := filepath.Join(dir, name)
		if err := saveMultipartFile(header, target); err != nil {
			return nil, err
		}
		absolute, err := filepath.Abs(target)
		if err != nil {
			return nil, err
		}
		paths = append(paths, absolute)
	}
	return paths, nil
}

func saveMultipartFile(header *multipart.FileHeader, target string) error {
	source, err := header.Open()
	if err != nil {
		return err
	}
	defer source.Close()
	output, err := os.Create(target)
	if err != nil {
		return err
	}
	defer output.Close()
	_, err = io.Copy(output, source)
	return err
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
	events, err := s.store.ListSecurityEvents(c.Request.Context(), limit,
		c.Query("kind"), c.Query("app_package"))
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

func (s *Server) getClientConfig(c *gin.Context) {
	appPackage := c.Query("app_package")
	if appPackage == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "app_package required"})
		return
	}
	config, err := s.store.GetClientConfig(c.Request.Context(), appPackage)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ruleVersion := 0
	if latest, err := s.store.LatestRulePackage(c.Request.Context(), appPackage); err == nil && latest != nil {
		ruleVersion = latest.Version
	}
	c.JSON(http.StatusOK, gin.H{
		"app_package":  config.AppPackage,
		"detection":    config.Detection,
		"response":     config.Response,
		"policies":     config.Policies,
		"rule_version": ruleVersion,
	})
}

func (s *Server) setClientConfig(c *gin.Context) {
	var request struct {
		AppPackage string            `json:"app_package"`
		Detection  bool              `json:"detection"`
		Response   string            `json:"response"`
		Policies   map[string]string `json:"policies"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || request.AppPackage == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "app_package required"})
		return
	}
	if request.Response != "log" && request.Response != "toast" && request.Response != "block" && request.Response != "degrade" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "response must be log, toast, degrade or block"})
		return
	}
	if request.Policies == nil {
		request.Policies = map[string]string{}
	}
	for rule, response := range request.Policies {
		if !knownDetectionRule(rule) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown detection rule: " + rule})
			return
		}
		if response != "log" && response != "toast" && response != "block" && response != "degrade" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "policy response must be log, toast, degrade or block"})
			return
		}
	}
	config := store.ClientConfig{
		AppPackage: request.AppPackage,
		Detection:  request.Detection,
		Response:   request.Response,
		Policies:   request.Policies,
	}
	if err := s.store.SetClientConfig(c.Request.Context(), config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, config)
}

func knownDetectionRule(rule string) bool {
	switch rule {
	case "env_frida", "env_xposed", "env_injection", "env_unpacker",
		"env_hook", "env_debugger", "env_root", "env_emulator", "file_tamper",
		"yidun_root", "yidun_mount", "yidun_debug", "yidun_hook",
		"yidun_xposed", "yidun_injection", "yidun_emulator",
		"yidun_ld_preload", "yidun_dex":
		return true
	default:
		return false
	}
}

func (s *Server) publishRulePackage(c *gin.Context) {
	appPackage := c.Query("app_package")
	version, err := strconv.Atoi(c.DefaultQuery("version", "0"))
	if appPackage == "" || err != nil || version <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "app_package and positive version required"})
		return
	}
	if filepath.Base(appPackage) != appPackage {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid app_package"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2<<20)
	data, err := io.ReadAll(c.Request.Body)
	if err != nil || len(data) < 32 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule package required"})
		return
	}
	if len(data) < 4 || string(data[:4]) != "PKR1" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "not a PKR1 package"})
		return
	}
	dir := filepath.Join(s.cfg.DataDir, "rules", appPackage)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	path := filepath.Join(dir, fmt.Sprintf("%d.pkr", version))
	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, 0o644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := os.Rename(temp, path); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	digest := sha256.Sum256(data)
	sha := hex.EncodeToString(digest[:])
	if err := s.store.PublishRulePackage(c.Request.Context(), appPackage, version, sha, path); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"app_package": appPackage,
		"version":     version,
		"sha256":      sha,
	})
}

func (s *Server) latestRulePackage(c *gin.Context) {
	appPackage := c.Query("app_package")
	current, _ := strconv.Atoi(c.DefaultQuery("current", "0"))
	if appPackage == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "app_package required"})
		return
	}
	rule, err := s.store.LatestRulePackage(c.Request.Context(), appPackage)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if rule == nil || rule.Version <= current {
		c.Status(http.StatusNoContent)
		return
	}
	data, err := os.ReadFile(rule.Path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule package missing"})
		return
	}
	c.Header("X-Rule-Version", strconv.Itoa(rule.Version))
	c.Data(http.StatusOK, "application/octet-stream", data)
}
