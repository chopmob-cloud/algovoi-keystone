"""Entry-point shim. The runnable service lives in the package
(``algovoi_retention_chain.service``) so it ships inside the wheel; this aliases
``app.main`` to it, keeping the Docker image's ``uvicorn app.main:app`` working
unchanged while ``pip install`` + the console script run the same service.
"""
import sys

from algovoi_retention_chain import service as _service

sys.modules[__name__] = _service
