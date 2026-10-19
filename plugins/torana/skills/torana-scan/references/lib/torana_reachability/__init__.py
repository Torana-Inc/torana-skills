"""torana-reachability: the one reachability engine (REACHABILITY_EXTRACTOR.md § 3.3.1, decisions D1 and D9).

Does this tree import a package, and can an entry point reach this function? Deterministic, no model, no network,
no clock in any output. Stdlib only, plus OPTIONAL `tree_sitter` + `tree_sitter_python` for the call graph.
⛔ No platform import: the `torana-scan` skill vendors this package and Atlas pins it (`scripts/vendor_reachability.sh`).

    index.build_imports(tree)        -> index/imports.json   (spans of a grammar superset, § 3.3.2.1)
    callgraph.build_callgraph_index  -> index/callgraph.json (Python, § 3.3.2.2)
    answer.answer(question, components, graph) -> verdict + evidence + certainty (§ 3.11)
"""
__version__ = "1.1.0"
ENGINE = "torana-reachability/1"
#: The engine string evidence carries (§ 3.11.6, § 3.12.6).
ENGINE_VERSION = f"torana-reachability/{__version__}"
ANALYZER_IMPORTS = "import-index/2"
ANALYZER_CALLGRAPH = "callgraph/2"
