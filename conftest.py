# Root conftest: ensures the repo root is on sys.path so tests can import
# app, detector and collector directly regardless of pytest invocation.
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault(
    'DB_FILE',
    os.path.join(tempfile.gettempdir(), f'threatwatch-tests-{os.getpid()}.sqlite'),
)
