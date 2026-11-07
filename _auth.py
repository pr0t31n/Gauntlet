import sys as _sys
from pathlib import Path as _Path
if "/opt/pr0t31n/shared" not in _sys.path:
    _sys.path.insert(0, "/opt/pr0t31n/shared")
import pr0t31n_auth as _mod
_mod.configure(
    app_dir=_Path(__file__).parent,
    public_paths={"/login", "/logout", "/api/nexus-status"},
    redirect_next="path",
    app_name="Gauntlet",
    version_check_tools=["Gearbox"],
)
from pr0t31n_auth import *
