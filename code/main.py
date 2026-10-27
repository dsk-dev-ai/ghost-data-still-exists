#!/usr/bin/env python3
import os
import sys
import subprocess

CODE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(CODE_DIR)

def main():
    solver = os.path.join(CODE_DIR, 'solver.py')
    if not os.path.exists(solver):
        for name in ['solver_final.py', 'solver_precise.py', 'deep_solve2.py']:
            cand = os.path.join(REPO_ROOT, name)
            if os.path.exists(cand):
                solver = cand
                break
    result = subprocess.run([sys.executable, solver], cwd=REPO_ROOT)
    sys.exit(result.returncode)

if __name__ == '__main__':
    main()
