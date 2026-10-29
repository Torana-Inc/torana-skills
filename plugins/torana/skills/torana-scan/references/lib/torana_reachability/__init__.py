"""torana-reachability: the one reachability engine (REACHABILITY_EXTRACTOR.md § 3.3.1, decisions D1 and D9).

Does this tree import a package, and can an entry point reach this function? Deterministic, no model, no network,
no clock in any output. Stdlib only, plus OPTIONAL `tree_sitter` and one grammar per language for the call graph
(`tree_sitter_python`; `tree_sitter_javascript` / `tree_sitter_typescript` read the npm file set, and no
reader consumes them yet — `js_front.py` is the front end, not an answer).
⛔ No platform import: the `torana-scan` skill vendors this package and Atlas pins it (`scripts/vendor_reachability.sh`).

    index.build_imports(tree)        -> index/imports.json   (spans of a grammar superset, § 3.3.2.1)
    callgraph.build_callgraph_index  -> index/callgraph.json (Python, § 3.3.2.2)
    answer.answer(question, components, graph) -> verdict + evidence + certainty (§ 3.11)
    manifests.read_manifests(tree)   -> declared ranges + resolved versions, each with file:line (1.9.0, OI-190)
    policy.admits(eco, spec, version) -> does a declared range admit a version (1.9.0, OI-191)
"""
__version__ = "1.16.1"
ENGINE = "torana-reachability/1"
#: The engine string evidence carries (§ 3.11.6, § 3.12.6).
ENGINE_VERSION = f"torana-reachability/{__version__}"
ANALYZER_IMPORTS = "import-index/2"
ANALYZER_CALLGRAPH = "callgraph/3"
#: The stored index documents' format (CODE_WALKER.md § 3.3.1); a document without the header field is format 1.
#: 4 = `lib_ref`, `class_base`, `module_import.from_import` (FIX_KNOWLEDGE_CONVERGENCE § 3.6.3).
#: 5 = the `npm` block: the JS/TS front end's own files and `module_import` / `lib_call` / `lib_ref` records,
#: which is what takes the npm API-diff check off word matching. `entry` records and reachability stay
#: Python-only, and `graph_from_index` still says so.
INDEX_FORMAT = 5

# The consumer API (§ 3.3.3). Imported last: the submodules read the constants above.
from .api import Index, dumps, index_tree, usage_records  # noqa: E402
from .grammar import ABSENCE_PROVEN  # noqa: E402
from .index import PARITY_PROVEN, import_sites  # noqa: E402

__all__ = ["ABSENCE_PROVEN", "ANALYZER_CALLGRAPH", "ANALYZER_IMPORTS", "ENGINE", "ENGINE_VERSION", "INDEX_FORMAT", "Index",
           "PARITY_PROVEN", "__version__", "dumps", "import_sites", "index_tree", "usage_records"]
