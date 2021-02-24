rbtree = static_library(
	'rbtree',
	['rbtree.c'],
	dependencies: [
		libbsd_dep,
	],
	pic: true,
)

rbtree_dep = declare_dependency(
	link_with: rbtree,
	dependencies: [
		libbsd_dep,
	],
)
