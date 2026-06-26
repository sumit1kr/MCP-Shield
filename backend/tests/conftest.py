import os
import sys

# Add backend directory to sys.path so test runner can find app modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
