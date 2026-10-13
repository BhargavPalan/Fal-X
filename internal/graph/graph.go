// Package graph is the typed entity graph: the assets a run discovers, the typed
// relationships between them, and the per-fact evidence behind each.
//
// It is the open asset model the recon engine writes into. An entity is one thing
// (a host, an IP, a certificate); an edge is a typed, directed relationship between
// two entities; a fact is an observed property of an entity with the source that
// saw it, whether the observation touched the target, a confidence and the run.
//
// The package is deliberately thin: pure helpers (canonicalisation, the
// relationship taxonomy) have no database, and the writers take the *sql.Tx that
// store.DB.InTx hands out, so every statement runs as the transaction's tenant and
// row-level security is what scopes it.
package graph

// EntityType is the kind of thing an entity is. The set mirrors the open asset
// model: infrastructure, web, cloud, code and people.
type EntityType string

// The entity types, grouped as infrastructure, web, cloud, code and people.
const (
	TypeOrg           EntityType = "org"
	TypePerson        EntityType = "person"
	TypeEmail         EntityType = "email"
	TypeUsername      EntityType = "username"
	TypeDomain        EntityType = "domain"
	TypeHost          EntityType = "host"
	TypeIP            EntityType = "ip"
	TypeNetblock      EntityType = "netblock"
	TypeASN           EntityType = "asn"
	TypeCertificate   EntityType = "certificate"
	TypeService       EntityType = "service"
	TypeTechnology    EntityType = "technology"
	TypeURL           EntityType = "url"
	TypeEndpoint      EntityType = "endpoint"
	TypeParameter     EntityType = "parameter"
	TypeCloudResource EntityType = "cloud_resource"
	TypeBucket        EntityType = "bucket"
	TypeRepository    EntityType = "repository"
	TypeCredential    EntityType = "credential"
	TypeLeak          EntityType = "leak"
	TypeDocument      EntityType = "document"
	TypeFinding       EntityType = "finding"
)

// EdgeType is a typed, directed relationship. The direction is from the entity
// that owns or precedes the relationship to the one it points at.
type EdgeType string

// The edge types, each with the entity pairing it connects (see relationships).
const (
	RelSubdomainOf  EdgeType = "subdomain_of"  // host -> domain
	RelResolvesTo   EdgeType = "resolves_to"   // host -> ip
	RelInNetblock   EdgeType = "in_netblock"   // ip -> netblock
	RelAnnouncedBy  EdgeType = "announced_by"  // netblock -> asn
	RelPresentsCert EdgeType = "presents_cert" // service -> certificate
	RelSanOf        EdgeType = "san_of"        // certificate -> host
	RelMxFor        EdgeType = "mx_for"        // host -> domain
	RelNsFor        EdgeType = "ns_for"        // host -> domain
	RelHosts        EdgeType = "hosts"         // ip -> service
	RelRunsTech     EdgeType = "runs_tech"     // service|url -> technology
	RelServesURL    EdgeType = "serves_url"    // service -> url
	RelHasEndpoint  EdgeType = "has_endpoint"  // url -> endpoint
	RelHasParam     EdgeType = "has_param"     // endpoint -> parameter
	RelOwns         EdgeType = "owns"          // org -> domain|netblock|asn
	RelEmploys      EdgeType = "employs"       // org -> person
	RelHasEmail     EdgeType = "has_email"     // person -> email
	RelSiblingOf    EdgeType = "sibling_of"    // any <-> any (inferred)
	RelTakeoverOf   EdgeType = "takeover_of"   // host -> cloud_resource
	RelOriginOf     EdgeType = "origin_of"     // ip -> host (inferred)
	RelLeaks        EdgeType = "leaks"         // repository|url -> credential|leak
	RelFoundIn      EdgeType = "found_in"      // any -> document
)

// Ref is a resolved entity's primary key, handed back by Resolve and used to
// attach facts and edges.
type Ref int64

// Entity is one node of the graph.
type Entity struct {
	ID           int64
	Type         EntityType
	Key          string // canonical identity
	Display      string
	SeedDistance int
}

// Edge is one typed relationship between two entities.
type Edge struct {
	SrcID      int64
	DstID      int64
	Rel        EdgeType
	Confidence float64
	Inferred   bool
}

// Fact is one observed property of an entity.
type Fact struct {
	EntityID   int64
	Key        string
	Value      string
	Source     string
	Passive    bool
	Confidence float64
	RunPK      int64 // 0 when not tied to a run
}

// Seed is one starting point for a run: a target the operator named.
type Seed struct {
	Type EntityType
	Key  string
}
