package web

import (
	"log"
	"net/http"
	"time"

	"github.com/blackfly/reconkit/internal/repository"
)

// ── GET /api/scans ────────────────────────────────────────────────────────────

type scanSummary struct {
	ID         int64   `json:"id"`
	Status     string  `json:"status"`
	Profile    string  `json:"profile"`
	StartedAt  string  `json:"started_at"`
	FinishedAt *string `json:"finished_at"`
	IsRunning  bool    `json:"is_running"`
}

func (s *Server) handleAPIListScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListScans()
	if err != nil {
		log.Printf("[api] list scans: %v", err)
		respondJSON(w, http.StatusInternalServerError, apiError{Error: "failed to list scans"})
		return
	}

	resp := make([]scanSummary, 0, len(scans))
	for _, sc := range scans {
		sum := scanSummary{
			ID:        sc.ID,
			Status:    string(sc.Status),
			Profile:   sc.Profile,
			StartedAt: sc.StartedAt.Format(time.RFC3339),
			IsRunning: s.scanManager.IsRunning(sc.ID),
		}
		if sc.FinishedAt != nil {
			t := sc.FinishedAt.Format(time.RFC3339)
			sum.FinishedAt = &t
		}
		resp = append(resp, sum)
	}
	respondJSON(w, http.StatusOK, resp)
}

// ── GET /api/scans/{id} ───────────────────────────────────────────────────────

type scanStatusResponse struct {
	scanSummary
	Stats *repository.ScanStats `json:"stats"`
}

func (s *Server) handleAPIScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID, err := parseScanID(r)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, apiError{Error: "invalid scan ID"})
		return
	}

	scan, err := s.store.GetScan(scanID)
	if err != nil {
		respondJSON(w, http.StatusNotFound, apiError{Error: "scan not found"})
		return
	}

	stats, err := s.store.GetScanStats(scanID)
	if err != nil {
		log.Printf("[api] get stats: %v", err)
		stats = &repository.ScanStats{}
	}

	sum := scanSummary{
		ID:        scan.ID,
		Status:    string(scan.Status),
		Profile:   scan.Profile,
		StartedAt: scan.StartedAt.Format(time.RFC3339),
		IsRunning: s.scanManager.IsRunning(scanID),
	}
	if scan.FinishedAt != nil {
		t := scan.FinishedAt.Format(time.RFC3339)
		sum.FinishedAt = &t
	}

	respondJSON(w, http.StatusOK, scanStatusResponse{scanSummary: sum, Stats: stats})
}

// ── GET /api/scans/{id}/events  (SSE) ─────────────────────────────────────────

func (s *Server) handleSSEStream(w http.ResponseWriter, r *http.Request) {
	scanID, err := parseScanID(r)
	if err != nil {
		http.Error(w, "invalid scan ID", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering

	// If scan already finished, send a single done event and return.
	if !s.scanManager.IsRunning(scanID) {
		writeSSE(w, "done", "")
		return
	}

	ch, unsub := s.scanManager.Subscribe(scanID)
	defer unsub()

	for {
		select {
		case event, ok := <-ch:
			if !ok {
				// broadcaster closed — scan ended
				writeSSE(w, "done", "")
				return
			}
			writeSSE(w, event.Event, event.Data)
		case <-r.Context().Done():
			return
		}
	}
}

// ── POST /api/scans/{id}/cancel ───────────────────────────────────────────────

func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	scanID, err := parseScanID(r)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, apiError{Error: "invalid scan ID"})
		return
	}

	if !s.scanManager.Cancel(scanID) {
		respondJSON(w, http.StatusNotFound, apiError{Error: "scan not running"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
