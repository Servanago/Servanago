package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/servanago/servanago/internal/caddycfg"
	"github.com/servanago/servanago/internal/config"
	"github.com/servanago/servanago/internal/store"
)

type snippetRow struct {
	store.Snippet
	Users []string // primary hostnames of the sites that have it attached
}

func (s *Server) snippetsPage(w http.ResponseWriter, r *http.Request) {
	all, err := s.deps.Store.ListSnippets(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rows := make([]snippetRow, len(all))
	for i, x := range all {
		rows[i].Snippet = x
		if rows[i].Users, err = s.deps.Store.SnippetUsers(r.Context(), x.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.render(w, "snippets", http.StatusOK, page{Title: "Snippets", Data: rows})
}

// snippetBody normalizes the posted body and checks it adapts; Mutate then checks Caddy loads it.
func snippetBody(r *http.Request) (string, error) {
	body := strings.TrimSpace(strings.ReplaceAll(r.PostFormValue("body"), "\r\n", "\n"))
	if _, err := caddycfg.AdaptSnippet(body); err != nil {
		return "", err
	}
	return body, nil
}

func (s *Server) addSnippet(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if err := config.ValidateSnippetName(name); err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	body, err := snippetBody(r)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	err = s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		_, err := tx.CreateSnippet(r.Context(), name, body)
		return err
	})
	if err != nil {
		failErr(w, err)
		return
	}
	s.audit(r, "snippet.created", name)
	w.Header().Set("HX-Redirect", "/snippets")
	w.WriteHeader(http.StatusNoContent)
}

// snippetByID finds the snippet in the transaction's view; false answers the request with 404.
func (s *Server) snippetByID(w http.ResponseWriter, r *http.Request, q *store.Store) (store.Snippet, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad snippet id")
		return store.Snippet{}, false
	}
	all, err := q.ListSnippets(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return store.Snippet{}, false
	}
	for _, x := range all {
		if x.ID == id {
			return x, true
		}
	}
	fail(w, http.StatusNotFound, "no such snippet")
	return store.Snippet{}, false
}

func (s *Server) updateSnippet(w http.ResponseWriter, r *http.Request) {
	cur, ok := s.snippetByID(w, r, s.deps.Store)
	if !ok {
		return
	}
	body, err := snippetBody(r)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error { return tx.UpdateSnippet(r.Context(), cur.ID, body) }); err != nil {
		failErr(w, err)
		return
	}
	s.audit(r, "snippet.updated", cur.Name)
	w.Header().Set("HX-Redirect", "/snippets")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteSnippet(w http.ResponseWriter, r *http.Request) {
	cur, ok := s.snippetByID(w, r, s.deps.Store)
	if !ok {
		return
	}
	err := s.deps.Apply.Mutate(r.Context(), func(tx *store.Store) error {
		users, err := tx.SnippetUsers(r.Context(), cur.ID)
		if err != nil {
			return err
		}
		if len(users) > 0 {
			return userError{http.StatusConflict, fmt.Sprintf("Used by %s. Detach it from those sites first.", strings.Join(users, ", "))}
		}
		return tx.DeleteSnippet(r.Context(), cur.ID)
	})
	if err != nil {
		failErr(w, err)
		return
	}
	s.audit(r, "snippet.deleted", cur.Name)
	w.Header().Set("HX-Redirect", "/snippets")
	w.WriteHeader(http.StatusNoContent)
}
