import sys
from angr import sim_options as so

DATASET = "cgc"
ROOT = sys.path[0]

RESOURCES_PATH = f"{ROOT}/resources"
CONFIG_PATH = f"{ROOT}/syml/config"
DATASET_PATH = f"{ROOT}/dataset"

RAW_PATH = f"{DATASET_PATH}/features.{{cb}}.{{pov}}.raw"
PROCESSED_PATH = f"{DATASET_PATH}/features.processed"  # {{cb}}.{{pov}}

add_options = {so.MEMORY_SYMBOLIC_BYTES_MAP, so.TRACK_ACTION_HISTORY, so.CONCRETIZE_SYMBOLIC_WRITE_SIZES,
               so.CONCRETIZE_SYMBOLIC_FILE_READ_SIZES, so.TRACK_MEMORY_ACTIONS, so.COPY_STATES,
               so.STRICT_PAGE_ACCESS, so.ENABLE_NX,
               so.ZERO_FILL_UNCONSTRAINED_MEMORY, so.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY}
remove_options = {so.TRACK_REGISTER_ACTIONS, so.TRACK_TMP_ACTIONS, so.TRACK_JMP_ACTIONS,
                  so.ACTION_DEPS, so.TRACK_CONSTRAINT_ACTIONS, so.LAZY_SOLVES, so.SIMPLIFY_MEMORY_WRITES,
                  so.ALL_FILES_EXIST}
