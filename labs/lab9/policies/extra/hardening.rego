# Two checks the shipped k8s-security.rego does not make.
# Own package so conftest loads it alongside the shipped rules under --all-namespaces.
package k8s.security.extra

# deny: images must be pinned by digest, not a mutable tag. The shipped policy
# only bans :latest, so bkimminich/juice-shop:v20.0.0 slips past it even though a
# tag can be re-pointed at different content (the Lab 8 swap attack).
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q must pin its image by digest, not a tag (%s)", [c.name, c.image])
}

# warn: a memory limit above 1Gi lets one pod reserve an outsized slice of a node.
# The shipped policy checks that a limit EXISTS; it never checks its magnitude.
warn contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	limit := c.resources.limits.memory
	units.parse_bytes(limit) > units.parse_bytes("1Gi")
	msg := sprintf("container %q memory limit %s exceeds the 1Gi ceiling", [c.name, limit])
}
