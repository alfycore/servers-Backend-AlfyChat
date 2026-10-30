package servers

import (
	"encoding/json"
	"strings"
	"testing"
)

const sampleTemplate = `{"code":"abc","name":"Modèle","serialized_source_guild":{"name":"Club Photo","description":"Un club",
 "roles":[{"id":0,"name":"@everyone","color":0,"permissions":"104324673"},
          {"id":1,"name":"Modération","color":3447003,"hoist":true,"permissions":"8"},
          {"id":2,"name":"Membre","color":0,"permissions":"3072"}],
 "channels":[
  {"id":10,"name":"Vocal","type":4,"position":1,"parent_id":null,"permission_overwrites":[]},
  {"id":11,"name":"Infos","type":4,"position":0,"parent_id":null,"permission_overwrites":[{"id":0,"type":0,"allow":"0","deny":"2048"},{"id":"123456789012345678","type":1,"allow":"2048","deny":"0"}]},
  {"id":12,"name":"annonces","type":5,"position":0,"parent_id":11,"topic":"Les news","permission_overwrites":[{"id":0,"type":0,"allow":"0","deny":"2048"},{"id":1,"type":0,"allow":"2048","deny":"0"}]},
  {"id":13,"name":"général","type":0,"position":0,"parent_id":null,"permission_overwrites":[]},
  {"id":14,"name":"Salon 1","type":2,"position":0,"parent_id":10,"user_limit":5,"permission_overwrites":[]},
  {"id":15,"name":"règles","type":0,"position":1,"parent_id":11,"permission_overwrites":[]},
  {"id":16,"name":"fil","type":11,"position":0,"parent_id":13,"permission_overwrites":[]}
 ]}}`

func TestBuildPlan(t *testing.T) {
	var tpl discordTemplate
	dec := json.NewDecoder(strings.NewReader(sampleTemplate))
	dec.UseNumber()
	if err := dec.Decode(&tpl); err != nil {
		t.Fatal(err)
	}
	p := buildPlan(&tpl, "everyone-id")
	if p.name != "Club Photo" || len(p.roles) != 3 || !p.roles[0].isDefault || p.roles[0].id != "everyone-id" {
		t.Fatalf("rôles : %+v", p.roles)
	}
	if p.roles[1].perms != pAdmin || p.roles[1].color != "#3498DB" || !p.roles[1].hoist {
		t.Fatalf("rôle modération : %+v", p.roles[1])
	}
	if p.roles[2].perms != pRead|pSend {
		t.Fatalf("rôle membre : %d", p.roles[2].perms)
	}
	var order []string
	for _, c := range p.channels {
		order = append(order, c.typ+":"+c.name)
	}
	want := "text:général,category:Infos,announcement:annonces,text:règles,category:Vocal,voice:Salon 1"
	if strings.Join(order, ",") != want {
		t.Fatalf("ordre : %s", strings.Join(order, ","))
	}
	ann := p.channels[2]
	if ann.parentID != p.channels[1].id || ann.topic != "Les news" || len(ann.overrides) != 2 {
		t.Fatalf("annonces : %+v", ann)
	}
	if ann.overrides[0].roleID != "everyone-id" || ann.overrides[0].deny != pSend || ann.overrides[1].allow != pSend {
		t.Fatalf("surcharges : %+v", ann.overrides)
	}
	if p.skippedChannels != 1 || p.skippedOverrides != 1 {
		t.Fatalf("ignorés : %d salons, %d surcharges", p.skippedChannels, p.skippedOverrides)
	}
	if p.channels[5].userLimit != 5 {
		t.Fatalf("limite vocale : %d", p.channels[5].userLimit)
	}
}

func TestTemplateCode(t *testing.T) {
	for in, want := range map[string]string{
		"https://discord.new/aBc123":       "aBc123",
		"discord.com/template/XyZ-9_q?x=1": "XyZ-9_q",
		"  aBc123 ":                        "aBc123",
		"https://discord.new/":             "",
		"https://discord.new/<script>":     "",
	} {
		if got := templateCode(in); got != want {
			t.Errorf("%q → %q, attendu %q", in, got, want)
		}
	}
}
