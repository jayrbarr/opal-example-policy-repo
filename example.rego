package graphql.authz

import future.keywords.in
import future.keywords.every

default allow := false

query_ast := graphql.parse(input.query, input.sdl)
user := split(input.auth, "Basic ")[1]
queryPolicy := data.queryPolicy[user]

nodes[node] {
    some node
    walk(query_ast, node)
}

all_queries := [ operation |
    [_, operation] = nodes[_]
    operation.Operation == "query"
    operation.SelectionSet
]

allow {
    all_queries != []
    every query in all_queries {
        every top_level in query.SelectionSet {
            queryPolicy.allowedQueries[top_level.Name]
            walk_top := [field |
				[_, field] := walk(top_level)
			]
			every field in walk_top {
				checkRestrictedFields(queryPolicy.allowedQueries[top_level.Name], field)
			}
        }
    }
}

checkRestrictedFields(policy, field) {
	not policy.restrictedFields
}

checkRestrictedFields(policy, field) {
	not policy.restrictedFields[field]
}
