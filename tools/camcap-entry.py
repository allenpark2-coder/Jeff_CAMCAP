"""PyInstaller entry point.

PyInstaller 需要一個真的 script 檔當進入點；它沒有 python 的 `-m <module>` 語意
（PyInstaller 的 `-m` 是 `--manifest` 的 deprecated 縮寫，會把後面的字當成
manifest 檔名，然後因為沒有 positional scriptname 而失敗）。
"""
import multiprocessing
import sys

from camcap.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()  # 凍結後的 exe 若有子行程，少了這行會無限重開自己
    sys.exit(main())
