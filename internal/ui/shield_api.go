package ui

import (
	"encoding/json"
	"io"
	"net/http"

	"gamecrack-scanner/internal/shield"
)

// ShieldActive reports whether Active Process Shield or Anti-Ransomware Guard is currently running.
func (s *Server) ShieldActive() bool {
	if s.shieldMgr == nil {
		return false
	}
	return s.shieldMgr.Active()
}

// ShieldStates returns (processShieldOn, ransomGuardOn, downloadGuardOn) for the Windows System Tray menu.
func (s *Server) ShieldStates() (bool, bool, bool) {
	wOn := s.WatchActive()
	if s.shieldMgr == nil {
		return false, false, wOn
	}
	st := s.shieldMgr.Status()
	return st.ProcessShieldOn, st.RansomGuardOn, wOn
}

// ToggleProcessShield flips the Active Process Shield on/off from the Windows System Tray menu.
func (s *Server) ToggleProcessShield() {
	if s.shieldMgr == nil {
		return
	}
	st := s.shieldMgr.Status()
	_ = s.shieldMgr.ApplyConfig(shield.Config{
		ProcessShieldOn: !st.ProcessShieldOn,
		ProcessAutoKill: st.ProcessAutoKill,
		RansomGuardOn:   st.RansomGuardOn,
	})
}

// ToggleRansomGuard flips the Anti-Ransomware Canary Guard on/off from the Windows System Tray menu.
func (s *Server) ToggleRansomGuard() {
	if s.shieldMgr == nil {
		return
	}
	st := s.shieldMgr.Status()
	_ = s.shieldMgr.ApplyConfig(shield.Config{
		ProcessShieldOn: st.ProcessShieldOn,
		ProcessAutoKill: st.ProcessAutoKill,
		RansomGuardOn:   !st.RansomGuardOn,
	})
}

func (s *Server) requireLocalShield(w http.ResponseWriter) bool {
	if s.opts.PublicMode || s.shieldMgr == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Active Protection & Kernel WFP hanya tersedia di aplikasi desktop lokal"})
		return false
	}
	return true
}

func (s *Server) handleShieldStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalShield(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.shieldMgr.Status())
}

func (s *Server) handleShieldConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalShield(w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cur := s.shieldMgr.Status()
	cfg := shield.Config{
		ProcessShieldOn: cur.ProcessShieldOn,
		ProcessAutoKill: cur.ProcessAutoKill,
		RansomGuardOn:   cur.RansomGuardOn,
	}
	var req struct {
		ProcessShieldOn *bool `json:"process_shield_on"`
		ProcessAutoKill *bool `json:"process_auto_kill"`
		RansomGuardOn   *bool `json:"ransom_guard_on"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.ProcessShieldOn != nil {
		cfg.ProcessShieldOn = *req.ProcessShieldOn
	}
	if req.ProcessAutoKill != nil {
		cfg.ProcessAutoKill = *req.ProcessAutoKill
	}
	if req.RansomGuardOn != nil {
		cfg.RansomGuardOn = *req.RansomGuardOn
	}
	if err := s.shieldMgr.ApplyConfig(cfg); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.shieldMgr.Status())
}

func (s *Server) handleShieldNetWatch(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalShield(w) {
		return
	}
	conns, err := s.shieldMgr.ListConnections()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"connections": conns,
		"count":       len(conns),
	})
}

func (s *Server) handleShieldBlock(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalShield(w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ExePath string `json:"exe_path"`
		PID     uint32 `json:"pid"`
		KillNow bool   `json:"kill_now"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if err := s.shieldMgr.BlockAppWFP(req.ExePath, req.PID, req.KillNow); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.shieldMgr.Status())
}

func (s *Server) handleShieldUnblock(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalShield(w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ExePath string `json:"exe_path"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if err := s.shieldMgr.UnblockAppWFP(req.ExePath); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.shieldMgr.Status())
}

func (s *Server) handleShieldKill(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalShield(w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PID     uint32 `json:"pid"`
		Suspend bool   `json:"suspend"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil || req.PID <= 4 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "PID tidak valid"})
		return
	}
	var err error
	if req.Suspend {
		err = shield.SuspendProcess(req.PID)
	} else {
		_ = shield.SuspendProcess(req.PID)
		err = shield.KillProcess(req.PID)
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleShieldCFA(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocalShield(w) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Enable bool `json:"enable"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if err := s.shieldMgr.SetDefenderCFA(req.Enable); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.shieldMgr.Status())
}
