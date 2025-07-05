# Contributing to E-Gov Guardian

First off, thanks for taking the time to contribute!

The following is a quick guide; for anything bigger, please open an issue first so we can discuss it.

## 📑 Ground Rules

1. **Be respectful** – we value inclusive, polite discussion.
2. **No sensitive data** – never commit real API keys, secrets or customer data.
3. **Follow project style** – run `flake8` and `mypy` before committing.
4. **One feature per PR** – small, focused pull-requests are easier to review.

## 🛠️ Getting Started

```bash
# fork & clone
 git clone https://github.com/YOUR_USER/E-Gov_Guardian.git
 cd E-Gov_Guardian

# create venv & install deps
 python -m venv .venv
 source .venv/bin/activate
 pip install -r requirements.txt
```

Run tests:

```bash
pytest -q
```

## 🚀 Adding a New Security Check (example)

1. Create a new file under `scanner/checks/your_check.py` implementing `run(url) -> List[Finding]`.
2. Import and call it from `scanner/advanced_tests.py` or relevant phase.
3. Add unit tests under `tests/`.
4. Update README if user-visible.

## 📝 Code of Conduct

This project follows the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) – by participating you agree to abide by its terms.
