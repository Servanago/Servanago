package web

import "net/http"

func (s *Server) helpPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "help", http.StatusOK, page{Title: "Help", Data: newHelpPage()})
}
