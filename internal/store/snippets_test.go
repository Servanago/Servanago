package store

import (
	"context"
	"reflect"
	"testing"
)

func TestSnippetsAttachDetachDelete(t *testing.T) {
	s, ctx := open(t), context.Background()
	b, err := s.CreateSnippet(ctx, "b_two", "encode gzip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSnippet(ctx, "a_one", "respond 404"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSnippet(ctx, "a_one", "x"); err == nil {
		t.Error("duplicate snippet name accepted")
	}
	r := site("a.example.com")
	r.Snippets = []string{"b_two", "a_one"}
	r, err = s.CreateSite(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a_one", "b_two"}; !reflect.DeepEqual(r.Snippets, want) { // attach order is by name
		t.Fatalf("snippets = %v, want %v", r.Snippets, want)
	}
	if ls, _ := s.ListSites(ctx); len(ls) != 1 || len(ls[0].Snippets) != 2 {
		t.Fatalf("ListSites snippets: %+v", ls)
	}
	if users, _ := s.SnippetUsers(ctx, b.ID); !reflect.DeepEqual(users, []string{"a.example.com"}) {
		t.Fatalf("users = %v", users)
	}
	if err := s.DeleteSnippet(ctx, b.ID); err == nil {
		t.Error("deleted a snippet that a site uses")
	}
	r.Snippets = []string{"nope"}
	if err := s.UpdateSite(ctx, r); err == nil {
		t.Error("attached an unknown snippet")
	}
	r.Snippets = nil
	if err := s.UpdateSite(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSite(ctx, r.ID); len(got.Snippets) != 0 {
		t.Fatalf("still attached: %v", got.Snippets)
	}
	if err := s.DeleteSnippet(ctx, b.ID); err != nil {
		t.Fatalf("delete unused: %v", err)
	}
}

func TestDeleteSiteDetachesSnippets(t *testing.T) {
	s, ctx := open(t), context.Background()
	x, _ := s.CreateSnippet(ctx, "keep_me", "encode gzip")
	r := site("a.example.com")
	r.Snippets = []string{"keep_me"}
	r, err := s.CreateSite(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSite(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSnippet(ctx, x.ID); err != nil {
		t.Fatalf("snippet still pinned by a deleted site: %v", err)
	}
}
