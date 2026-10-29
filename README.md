# Password Strength Analyzer and Entropy Calculator

A Linux command-line tool that evaluates password strength, estimates
theoretical entropy, detects common passwords via a local wordlist, and
provides security recommendations.

## Features

- Secure password prompt (no echo)
- Length and character-composition analysis
- Theoretical entropy: `H = L x log2(R)`
- zxcvbn guessability estimate and crack-time display
- Local common-password detection (no network access)
- Pattern detection: repeated chars, sequences, substitutions, predictable words
- Actionable security recommendations
- `--help`, `--version`, `--wordlist`, `--stdin`, `--no-color`

## Requirements

- Python 3.8+
- zxcvbn

## Installation

```bash
python3 -m pip install -r requirements.txt
# optional: install as a command
python3 -m pip install .
```

On Linux, make the script executable:

```bash
chmod +x password_analyzer.py
```

## Usage

```bash
# Interactive prompt
python3 password_analyzer.py

# Read password from stdin (for scripting/tests)
echo "MyP@ssw0rd!" | python3 password_analyzer.py --stdin

# Custom wordlist
python3 password_analyzer.py --wordlist /path/to/wordlist.txt

# Help
python3 password_analyzer.py --help
```

## Testing

```bash
python3 -m unittest discover -s tests -v
```

## Security notes

- Passwords are never stored or transmitted.
- Common-password checks use only the local wordlist file.
- Theoretical entropy is an upper bound assuming uniform random selection;
  real passwords are not uniform. zxcvbn estimates actual guessability.

## License

Educational use.
