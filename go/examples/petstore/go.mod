module github.com/keyorixhq/keyorix-sdks/go/examples/petstore

go 1.26.2

require (
	github.com/keyorixhq/keyorix-sdks/go v0.3.0
	github.com/lib/pq v1.12.3
)

// Sibling module in the same repo, not yet published/tagged — resolve
// locally rather than from the module proxy.
replace github.com/keyorixhq/keyorix-sdks/go => ../..
