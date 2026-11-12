package web

import (
	"bytes"
	"errors"
	"html/template"
	"io"
	"net/http"

	"github.com/deployguard/deployguard/internal/ai"
	"github.com/deployguard/deployguard/internal/domain"
	"github.com/deployguard/deployguard/internal/plan"
	"github.com/deployguard/deployguard/internal/risk"
)

type localHandler struct {
	history   LocalHistory // optional; nil keeps no history
	address   string
	engine    risk.Engine
	explainer *ai.Explainer
}

// NewLocalHandler returns the loopback-only handler for local mode. explainer may be nil.
func NewLocalHandler(address string, explainer *ai.Explainer) http.Handler {
	return NewLocalHandlerWithHistory(address, explainer, nil)
}

// NewLocalHandlerWithHistory is NewLocalHandler that also records each upload's verdict in history
// (never the plan) and serves them on /history. history may be nil.
func NewLocalHandlerWithHistory(address string, explainer *ai.Explainer, history LocalHistory) http.Handler {
	return &localHandler{address: address, engine: risk.NewEngine(risk.Config{}), explainer: explainer, history: history}
}

// ServeHTTP serves the upload page and analysis. Every request's Host must equal the configured
// address, and an upload must also carry a matching Origin; together they block DNS rebinding and
// cross-site uploads.
func (handler *localHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	writer.Header().Set("X-Frame-Options", "DENY")
	// Intentionally "same-origin", NOT "no-referrer". With no-referrer, browsers
	// send "Origin: null" on this page's own upload form, and the exact-Origin
	// check below then rejects every upload with 403. same-origin keeps the real
	// Origin on same-site POSTs and still sends no referrer to other sites.
	writer.Header().Set("Referrer-Policy", "same-origin")
	if request.Host != handler.address {
		http.Error(writer, "invalid host", http.StatusForbidden)
		return
	}
	if serveSiteAsset(writer, request) {
		return
	}
	if request.Method == http.MethodGet && request.URL.Path == "/assets/app.css" {
		serveStyles(writer)
		return
	}
	if request.Method == http.MethodGet && request.URL.Path == "/assets/theme.js" {
		serveThemeScript(writer)
		return
	}
	if request.Method == http.MethodGet && request.URL.Path == "/history" {
		handler.showHistory(writer)
		return
	}
	if request.Method == http.MethodGet && request.URL.Path == "/" {
		handler.render(writer, nil)
		return
	}
	if request.Method != http.MethodPost || request.URL.Path != "/analyze" {
		handler.fail(writer, "That page does not exist.", http.StatusNotFound)
		return
	}
	if request.Header.Get("Origin") != "http://"+handler.address {
		handler.fail(writer, "invalid request origin", http.StatusForbidden)
		return
	}
	if request.ContentLength > maxRequestBytes {
		handler.fail(writer, "request exceeds the size limit", http.StatusRequestEntityTooLarge)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	reader, err := request.MultipartReader()
	if err != nil {
		handler.fail(writer, "invalid multipart request", http.StatusBadRequest)
		return
	}
	part, err := reader.NextPart()
	if err != nil || part.FormName() != "plan" || part.FileName() == "" {
		handler.fail(writer, "Terraform JSON plan is required", http.StatusBadRequest)
		return
	}
	content, err := io.ReadAll(io.LimitReader(part, maxPlanBytes+1))
	defer clear(content)
	var maxErr *http.MaxBytesError
	if int64(len(content)) > maxPlanBytes || errors.As(err, &maxErr) {
		handler.fail(writer, "plan exceeds the size limit", http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil {
		handler.fail(writer, "plan upload could not be read", http.StatusBadRequest)
		return
	}
	_, err = reader.NextPart()
	if err != io.EOF {
		if errors.As(err, &maxErr) {
			handler.fail(writer, "request exceeds the size limit", http.StatusRequestEntityTooLarge)
		} else {
			handler.fail(writer, "unexpected upload fields", http.StatusBadRequest)
		}
		return
	}
	parsed, err := plan.Parse(bytes.NewReader(content))
	if err != nil {
		handler.fail(writer, "invalid Terraform plan JSON", http.StatusUnprocessableEntity)
		return
	}
	analysis, err := handler.engine.Analyze(parsed)
	if err != nil {
		handler.fail(writer, "plan analysis failed", http.StatusUnprocessableEntity)
		return
	}
	handler.recordUpload(content, analysis)
	analysis.AIExplanation = handler.explainer.Explain(request.Context(), analysis)
	handler.render(writer, &analysis)
}

func (handler *localHandler) render(writer http.ResponseWriter, analysis *domain.Analysis) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := localTemplate.Execute(writer, analysis); err != nil {
		http.Error(writer, "could not render page", http.StatusInternalServerError)
	}
}

var localTemplate = template.Must(template.New("local").Funcs(templateFuncs).Parse(sharedTemplates + localPage + resultTemplate + historyTemplate))

func (handler *localHandler) fail(writer http.ResponseWriter, message string, status int) {
	writeError(writer, localTemplate, errorData{
		Status: status, Message: sentence(message), BackHref: "/", BackLabel: "Back to the analyzer", Local: true, Mode: "LOCAL MODE",
	})
}
