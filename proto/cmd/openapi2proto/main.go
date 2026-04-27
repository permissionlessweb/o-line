// openapi2proto: OpenAPI 3.x to Proto3 generator, split by service.
//
// Reads a slim OpenAPI JSON spec, emits separate .proto files per API group:
//   cloudflare/v1/dns.proto     — DNS record management
//   cloudflare/v1/web3.proto    — Web3 IPFS gateway hostnames
//   cloudflare/v1/zones.proto   — Zone management
//
// Usage:
//   go run . -spec ../../../cloudflare/openapi.json -outdir ../../cloudflare/v1
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

type Spec struct {
	Info struct{ Title, Version string } `json:"info"`
	Paths map[string]map[string]json.RawMessage `json:"paths"`
	Components struct {
		Schemas map[string]Schema `json:"schemas"`
	} `json:"components"`
}
type Schema struct {
	Ref        string            `json:"$ref"`
	Type       string            `json:"type"`
	Format     string            `json:"format"`
	Properties map[string]Schema `json:"properties"`
	Items      *Schema           `json:"items"`
	Enum       []interface{}     `json:"enum"`
}
type Operation struct {
	OperationID string      `json:"operationId"`
	Summary     string      `json:"summary"`
	Parameters  []Parameter `json:"parameters"`
	RequestBody *struct {
		Content map[string]struct{ Schema Schema } `json:"content"`
	} `json:"requestBody"`
}
type Parameter struct {
	Name   string `json:"name"`
	In     string `json:"in"`
	Schema Schema `json:"schema"`
}

var nonAlpha = regexp.MustCompile(`[^a-zA-Z0-9]+`)
var allSchemas map[string]Schema

func pascal(s string) string {
	parts := strings.Split(nonAlpha.ReplaceAllString(s, "_"), "_")
	var b strings.Builder
	for _, p := range parts {
		if p != "" { b.WriteString(strings.ToUpper(p[:1]) + p[1:]) }
	}
	return b.String()
}
func snake(s string) string {
	var b strings.Builder
	for i, c := range s {
		if i > 0 && c >= 'A' && c <= 'Z' { b.WriteByte('_') }
		b.WriteRune(c)
	}
	return strings.ToLower(nonAlpha.ReplaceAllString(b.String(), "_"))
}
func refName(ref string) string {
	p := strings.Split(ref, "/"); return p[len(p)-1]
}
func protoType(s Schema) string {
	if s.Ref != "" {
		name := refName(s.Ref)
		if ref, ok := allSchemas[name]; ok && len(ref.Properties) == 0 && ref.Ref == "" {
			return protoType(ref)
		}
		return pascal(name)
	}
	switch s.Type {
	case "integer":
		if s.Format == "int64" { return "int64" }; return "int32"
	case "number": return "double"
	case "boolean": return "bool"
	case "array":
		if s.Items != nil { return protoType(*s.Items) }; return "string"
	default: return "string"
	}
}
func isRepeated(s Schema) bool { return s.Type == "array" }
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m { keys = append(keys, k) }
	sort.Strings(keys); return keys
}

type serviceGroup struct {
	Name     string // "dns", "web3", "zones"
	Package  string // "cloudflare.v1.dns"
	Service  string // "DnsService"
	Schemas  map[string]Schema
	RPCs     []rpcDef
}
type rpcDef struct {
	Name, Summary, Method, Path string
	Params  []Parameter
	BodyRef string
}

func classifyPath(path string) string {
	// Strip /zones/{zone_id}/ or /accounts/{account_id}/ prefix
	p := path
	for _, prefix := range []string{"/zones/{zone_identifier}/", "/zones/{zone_id}/", "/accounts/{account_id}/"} {
		if strings.HasPrefix(p, prefix) {
			p = p[len(prefix):]
			break
		}
	}
	// Top-level /zones or /accounts
	if p == "/zones" || strings.HasPrefix(p, "/zones/{") {
		return "zones"
	}
	if p == "/accounts" || strings.HasPrefix(p, "/accounts/{") {
		return "accounts"
	}
	// First segment is the group: dns_records -> dns, web3 -> web3, ssl -> ssl, etc.
	p = strings.TrimPrefix(p, "/")
	seg := strings.SplitN(p, "/", 2)[0]
	// Normalize: underscores to hyphens, strip _records suffix
	seg = strings.ReplaceAll(seg, "_", "-")
	seg = strings.TrimSuffix(seg, "-records")
	if seg == "" { return "misc" }
	return seg
}

func classifySchema(name string) string {
	lower := strings.ToLower(name)
	// Schema names are like "dns-records_xxx", "web3_xxx", "zones_xxx"
	if idx := strings.Index(lower, "_"); idx > 0 {
		prefix := lower[:idx]
		prefix = strings.TrimSuffix(prefix, "-records")
		return prefix
	}
	return "misc"
}

func writeProto(path string, g *serviceGroup, basePkg string) {
	if idx := strings.LastIndex(path, "/"); idx > 0 {
		os.MkdirAll(path[:idx], 0o755)
	}
	f, err := os.Create(path)
	if err != nil { fmt.Fprintf(os.Stderr, "Error: %v\n", err); return }
	defer f.Close()

	fmt.Fprintf(f, "// Cloudflare %s API\n", strings.Title(g.Name))
	fmt.Fprintf(f, "// Regenerate: go run ./proto/cmd/openapi2proto -spec cloudflare/openapi.json\n\n")
	fmt.Fprintf(f, "syntax = \"proto3\";\npackage %s.%s;\n\n", basePkg, strings.ReplaceAll(g.Name, "-", "_"))
	fmt.Fprintf(f, "import \"google/protobuf/struct.proto\";\n")
	fmt.Fprintf(f, "import \"google/api/annotations.proto\";\n\n")

	// Collect known message names in this file
	knownMsgs := map[string]bool{}
	for name, s := range g.Schemas {
		if len(s.Properties) > 0 || s.Ref != "" { knownMsgs[pascal(name)] = true }
	}

	// Schema messages
	for _, name := range sortedKeys(g.Schemas) {
		s := g.Schemas[name]
		if len(s.Properties) == 0 && s.Ref == "" { continue }
		if len(s.Properties) == 0 && s.Ref != "" {
			// Type alias — schema is just a $ref wrapper
			refType := protoType(Schema{Ref: s.Ref})
			fmt.Fprintf(f, "message %s {\n    %s value = 1;\n}\n\n", pascal(name), refType)
			continue
		}
		fmt.Fprintf(f, "message %s {\n", pascal(name))
		for i, pn := range sortedKeys(s.Properties) {
			ps := s.Properties[pn]
			pt := protoType(ps)
			// Cross-ref: if message type not in this file, use Struct
			if pt != "string" && pt != "int32" && pt != "int64" && pt != "double" && pt != "bool" && !knownMsgs[pt] && !strings.HasPrefix(pt, "google.") {
				pt = "google.protobuf.Struct"
			}
			if isRepeated(ps) {
				fmt.Fprintf(f, "    repeated %s %s = %d;\n", pt, func() string { fn := snake(pn); if fn == "" || (fn[0] >= '0' && fn[0] <= '9') { return "f_" + fn }; return fn }(), i+1)
			} else {
				fmt.Fprintf(f, "    %s %s = %d;\n", pt, func() string { fn := snake(pn); if fn == "" || (fn[0] >= '0' && fn[0] <= '9') { return "f_" + fn }; return fn }(), i+1)
			}
		}
		fmt.Fprintf(f, "}\n\n")
	}

	// RPC request/response messages
	for _, rpc := range g.RPCs {
		reqSuffix := "Request"
		respSuffix := "Response"
		if knownMsgs[rpc.Name+"Request"] || knownMsgs[rpc.Name+"Response"] {
			reqSuffix = "RpcRequest"
			respSuffix = "RpcResponse"
		}
		fmt.Fprintf(f, "message %s%s {\n", rpc.Name, reqSuffix)
		n := 1
		for _, p := range rpc.Params {
			pt := protoType(p.Schema)
			// If type is a message name not in this file, use Struct
			if pt != "string" && pt != "int32" && pt != "int64" && pt != "double" && pt != "bool" && !knownMsgs[pt] && !strings.HasPrefix(pt, "google.") {
				pt = "string"
			}
			fn := snake(p.Name); if fn == "" { fn = fmt.Sprintf("param_%d", n) }; fmt.Fprintf(f, "    %s %s = %d;\n", pt, fn, n); n++
		}
		if rpc.BodyRef != "" {
			if knownMsgs[rpc.BodyRef] {
				fmt.Fprintf(f, "    %s body = %d;\n", rpc.BodyRef, n)
			} else {
				fmt.Fprintf(f, "    google.protobuf.Struct body = %d; // cross-ref: %s\n", n, rpc.BodyRef)
			}
		} else if rpc.Method == "post" || rpc.Method == "put" || rpc.Method == "patch" {
			fmt.Fprintf(f, "    google.protobuf.Struct body = %d;\n", n)
		}
		fmt.Fprintf(f, "}\n\n")

		fmt.Fprintf(f, "message %s%s {\n", rpc.Name, respSuffix)
		fmt.Fprintf(f, "    bool success = 1;\n")
		fmt.Fprintf(f, "    google.protobuf.Struct result = 2;\n")
		fmt.Fprintf(f, "    repeated google.protobuf.Struct errors = 3;\n")
		fmt.Fprintf(f, "}\n\n")
	}

	// Service
	fmt.Fprintf(f, "service %s {\n", g.Service)
	for _, rpc := range g.RPCs {
		rs, rsp := "Request", "Response"
		if knownMsgs[rpc.Name+"Request"] || knownMsgs[rpc.Name+"Response"] { rs, rsp = "RpcRequest", "RpcResponse" }
		if rpc.Summary != "" { fmt.Fprintf(f, "    // %s\n", rpc.Summary) }
		fmt.Fprintf(f, "    rpc %s(%s%s) returns (%s%s) {\n", rpc.Name, rpc.Name, rs, rpc.Name, rsp)
		fmt.Fprintf(f, "        option (google.api.http) = {\n")
		fmt.Fprintf(f, "            %s: \"%s\"\n", rpc.Method, rpc.Path)
		if rpc.BodyRef != "" || rpc.Method == "post" || rpc.Method == "put" || rpc.Method == "patch" {
			fmt.Fprintf(f, "            body: \"*\"\n")
		}
		fmt.Fprintf(f, "        };\n    }\n")
	}
	fmt.Fprintf(f, "}\n")

	fmt.Fprintf(os.Stderr, "  %s: %d messages, %d RPCs\n", path, len(g.Schemas)+len(g.RPCs)*2, len(g.RPCs))
}

func main() {
	specFile := flag.String("spec", "", "OpenAPI JSON spec")
	outDir := flag.String("outdir", ".", "Output directory for .proto files")
	basePkg := flag.String("package", "cloudflare.v1", "Base proto package")
	flag.Parse()

	if *specFile == "" {
		fmt.Fprintln(os.Stderr, "Usage: openapi2proto -spec <file.json> [-outdir dir] [-package name]")
		os.Exit(1)
	}

	data, _ := os.ReadFile(*specFile)
	var spec Spec
	json.Unmarshal(data, &spec)

	allSchemas = spec.Components.Schemas

	// Initialize groups dynamically
	groups := map[string]*serviceGroup{}
	getGroup := func(name string) *serviceGroup {
		if g, ok := groups[name]; ok { return g }
		svcName := pascal(name) + "Service"
		groups[name] = &serviceGroup{Name: name, Service: svcName, Schemas: map[string]Schema{}}
		return groups[name]
	}

	// Classify schemas
	for name, s := range spec.Components.Schemas {
		grp := classifySchema(name)
		getGroup(grp).Schemas[name] = s
	}

	// Classify paths into RPCs
	seen := map[string]map[string]int{}
	for _, path := range sortedKeys(spec.Paths) {
		grp := classifyPath(path)
		for _, method := range []string{"get", "post", "put", "patch", "delete"} {
			raw, ok := spec.Paths[path][method]
			if !ok { continue }
			var op Operation
			json.Unmarshal(raw, &op)

			name := pascal(op.OperationID)
			if name == "" { name = pascal(method + "_" + path) }
			if seen[grp] == nil { seen[grp] = map[string]int{} }; if c := seen[grp][name]; c > 0 { name = fmt.Sprintf("%s%d", name, c) }
			seen[grp][name]++

			bodyRef := ""
			if op.RequestBody != nil {
				for _, mt := range op.RequestBody.Content {
					if mt.Schema.Ref != "" { bodyRef = pascal(refName(mt.Schema.Ref)) }
					break
				}
			}
			getGroup(grp).RPCs = append(getGroup(grp).RPCs, rpcDef{
				Name: name, Summary: op.Summary, Method: method, Path: path,
				Params: op.Parameters, BodyRef: bodyRef,
			})
		}
	}

	// Write each service to its own .proto
	fmt.Fprintln(os.Stderr, "Generating Cloudflare proto definitions:")
	for _, gName := range sortedKeys(groups) {
		g := groups[gName]
		if len(g.RPCs) == 0 && len(g.Schemas) == 0 { continue }
		outPath := fmt.Sprintf("%s/%s.proto", *outDir, g.Name)
		writeProto(outPath, g, *basePkg)
	}
}
