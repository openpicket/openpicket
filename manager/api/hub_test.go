package api

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"

	apiv1 "github.com/openpicket/openpicket/gen/openpicket/api/v1"
	"github.com/openpicket/openpicket/manager/auth"
)

// uploadHub posts a custom item with its data files.
func (e *env) uploadHub(c *clients, typ, stage, item string, data map[string]string) (int, string) {
	e.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("type", typ)
	_ = mw.WriteField("stage", stage)
	fw, _ := mw.CreateFormFile("item", "item.yaml")
	_, _ = fw.Write([]byte(item))
	for name, content := range data {
		fw, _ := mw.CreateFormFile("data", name)
		_, _ = fw.Write([]byte(content))
	}
	_ = mw.Close()
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/hub/upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-OpenPicket-Request", "1")
	res, err := c.http.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func TestHubUploadAndStates(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	if err := e.server.cfg.Hub.SeedBuiltin(ctx); err != nil {
		t.Fatal(err)
	}
	e.server.cfg.Auth.Roles = auth.Roles{Admin: auth.RoleConfig{Users: []string{"root"}}, Operator: auth.RoleConfig{Groups: []string{"secops"}}}
	op := e.clients(viewerHeaders("bob", "secops"))
	admin := e.clients(viewerHeaders("root", "secops"))
	item := "type: leaky\nname: me/bad-ua\ndescription: mine\nfilter: evt.Meta.log_type == 'suricata_alert'\ndata:\n  - source_url: https://example.invalid/ua.txt\n    dest_file: web/ua.txt\n"

	if c, _ := e.uploadHub(op, "scenarios", "", item, map[string]string{"ua.txt": "curl\n"}); c != http.StatusForbidden {
		t.Fatalf("operator upload: %d", c)
	}
	if c, msg := e.uploadHub(admin, "scenarios", "", item, nil); c != http.StatusBadRequest || !strings.Contains(msg, "web/ua.txt") {
		t.Fatalf("missing data file: %d %s", c, msg)
	}
	if c, msg := e.uploadHub(admin, "scenarios", "", item, map[string]string{"ua.txt": "curl\n", "other.txt": "x"}); c != http.StatusBadRequest || !strings.Contains(msg, "other.txt") {
		t.Fatalf("unrelated data file: %d %s", c, msg)
	}
	if c, msg := e.uploadHub(admin, "scenarios", "", item, map[string]string{"ua.txt": "curl\n"}); c != http.StatusOK {
		t.Fatalf("upload: %d %s", c, msg)
	}
	if c, msg := e.uploadHub(admin, "scenarios", "", "name: openpicket/compromised-host\n", nil); c != http.StatusBadRequest || !strings.Contains(msg, "builtin") {
		t.Fatalf("over a built-in item: %d %s", c, msg)
	}
	if c, msg := e.uploadHub(admin, "parsers", "../parse", "name: me/p\n", nil); c != http.StatusBadRequest {
		t.Fatalf("parser without a valid stage: %d %s", c, msg)
	}
	if c, msg := e.uploadHub(admin, "parsers", "s01-parse", "name: me/p\nfilter: evt.Parsed.program == 'me'\n", nil); c != http.StatusOK {
		t.Fatalf("parser: %d %s", c, msg)
	}

	list, err := admin.hub.ListHubItems(ctx, connect.NewRequest(&apiv1.ListHubItemsRequest{Type: "scenarios"}))
	if err != nil {
		t.Fatal(err)
	}
	var mine *apiv1.HubItem
	for _, it := range list.Msg.Items {
		if it.Name == "me/bad-ua" {
			mine = it
		}
	}
	if mine == nil || mine.Source != "custom" || mine.State != "simulation" || mine.Compat != "ok" || mine.Description != "mine" {
		t.Fatalf("uploaded item: %v", mine)
	}
	b, err := e.server.cfg.Hub.Bundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range b.Data {
		found = found || (f.Path == "web/ua.txt" && string(f.Content) == "curl\n")
	}
	if !found {
		t.Fatalf("data file not in the bundle: %v", b.Data)
	}
	// State changes are for admins.
	ref := &apiv1.HubRef{Type: "scenarios", Name: "me/bad-ua"}
	if _, err := op.hub.SetHubItemState(ctx, connect.NewRequest(&apiv1.SetHubItemStateRequest{Ref: ref, State: "enabled"})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("operator state change: %v", err)
	}
	if _, err := admin.hub.SetHubItemState(ctx, connect.NewRequest(&apiv1.SetHubItemStateRequest{Ref: ref, State: "bogus"})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("bogus state: %v", err)
	}
	if _, err := admin.hub.RemoveHubItem(ctx, connect.NewRequest(&apiv1.RemoveHubItemRequest{Ref: &apiv1.HubRef{Type: "scenarios", Name: "openpicket/compromised-host"}})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("removing a built-in item: %v", err)
	}
	if _, err := admin.hub.RemoveHubItem(ctx, connect.NewRequest(&apiv1.RemoveHubItemRequest{Ref: ref})); err != nil {
		t.Fatal(err)
	}
	if b, _ := e.server.cfg.Hub.Bundle(ctx); len(b.Data) != 0 {
		t.Fatalf("data file kept after removal: %v", b.Data)
	}
	// No hub source configured: the index calls say so.
	if _, err := admin.hub.ListHubIndex(ctx, connect.NewRequest(&apiv1.ListHubIndexRequest{})); code(err) != connect.CodeUnavailable {
		t.Fatalf("index without a hub: %v", err)
	}
}

func TestLogPrograms(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	e.server.cfg.Auth.Roles = auth.Roles{Admin: auth.RoleConfig{Users: []string{"root"}}}
	admin := e.clients(viewerHeaders("root", ""))
	lp := e.server.cfg.LogPrograms
	lp.Seen("web-01", "nginx", 10)
	lp.Seen("web-02", "nginx", 5)
	lp.Seen("db-01", "postgres", 3)
	lp.Flush(ctx)
	if c, msg := e.uploadHub(admin, "parsers", "s01-parse", "name: me/pg\nfilter: evt.Parsed.program == 'postgres'\n", nil); c != http.StatusOK {
		t.Fatalf("upload: %d %s", c, msg)
	}
	if _, err := admin.hub.SetLogProgramStorage(ctx, connect.NewRequest(&apiv1.SetLogProgramStorageRequest{Program: "nginx", Loki: false})); err != nil {
		t.Fatal(err)
	}
	res, err := admin.hub.ListLogPrograms(ctx, connect.NewRequest(&apiv1.ListLogProgramsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*apiv1.LogProgram{}
	for _, p := range res.Msg.Programs {
		got[p.Program] = p
	}
	if n := got["nginx"]; n == nil || n.Lines != 15 || len(n.Nodes) != 2 || len(n.Parsers) != 0 || n.Loki {
		t.Fatalf("nginx = %v", n)
	}
	if p := got["postgres"]; p == nil || len(p.Parsers) != 1 || p.Parsers[0] != "me/pg" || !p.Loki {
		t.Fatalf("postgres = %v", p)
	}
	if !lp.Skip("nginx") || lp.Skip("postgres") {
		t.Fatal("storage setting not applied")
	}
	if _, err := admin.hub.SetLogProgramStorage(ctx, connect.NewRequest(&apiv1.SetLogProgramStorageRequest{Program: " ", Loki: false})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("empty program: %v", err)
	}
}
