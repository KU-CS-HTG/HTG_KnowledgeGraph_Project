"""`security_kg/extraction/consts.py`를 불러오는 통로(원본이 `from consts import ...`를 쓰던 자리)."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("security_consts", ROOT / "extraction" / "consts.py")
consts = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(consts)
