# CryptoLink

Exchange file import and cataloging tool for tracing crypto transactions across suspects and exchanges.

## Windows: just run the .exe (no Python needed)

Go to the [Actions tab](../../actions/workflows/build-exe.yml), open the latest successful
run, and download the `CryptoLink-windows-exe` artifact - it contains `CryptoLink.exe`.
Double-click it; it starts the app and opens your browser automatically.

A new build is produced automatically every time `main.py` changes.

## Setup (from source)

```bash
pip install -r requirements.txt
python main.py
```

Then open http://127.0.0.1:5000 in your browser (opens automatically when run this way too).
