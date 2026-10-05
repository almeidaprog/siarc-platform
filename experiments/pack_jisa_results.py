from __future__ import annotations
import json, shutil
from datetime import datetime
from pathlib import Path

def main():
    root=Path('results/jisa')
    if not root.exists(): raise SystemExit('results/jisa does not exist.')
    stamp=datetime.now().strftime('%Y%m%d_%H%M%S')
    base=Path('results')/f'SIARC_JISA_RESULTS_{stamp}'
    archive=shutil.make_archive(str(base),'zip',root_dir='results',base_dir='jisa')
    print(archive)
if __name__=='__main__': main()
