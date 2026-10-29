#!/usr/bin/env python3
'''Password Strength Analyzer and Entropy Calculator - Linux CLI Tool.'''

import argparse
import getpass
import math
import os
import sys
from collections import Counter
from pathlib import Path

__version__ = '1.0.0'
APP_TITLE = 'Password Strength Analyzer and Entropy Calculator'

try:
    from zxcvbn import zxcvbn as _zxcvbn
    ZXCVBN_AVAILABLE = True
except Exception:
    _zxcvbn = None
    ZXCVBN_AVAILABLE = False

COMMON_BASE_WORDS = {
    'password', 'passw0rd', 'p@ssword', 'admin', 'administrator', 'welcome',
    'letmein', 'qwerty', 'abc123', 'iloveyou', 'monkey', 'dragon', 'master',
    'login', 'root', 'toor', 'guest', 'test', 'user', 'default', 'secret',
    'football', 'baseball', 'superman', 'batman', 'trustno1', 'sunshine',
    'princess', 'charlie', 'donald', 'password1', 'password123', '123456',
    '12345678', '123456789', 'qwerty123', 'welcome1', 'admin123',
}

SUBSTITUTIONS = {
    '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o',
    '$': 's', '5': 's', '7': 't', '+': 't', '8': 'b', '9': 'g',
}


def supports_color(stream=None):
    if stream is None:
        stream = sys.stdout
    if not getattr(stream, 'isatty', lambda: False)():
        return False
    if os.environ.get('NO_COLOR'):
        return False
    return True


def colorize(text, code, use_color=True):
    if not use_color:
        return text
    esc = chr(27)
    return esc + '[' + code + 'm' + text + esc + '[0m'


RATING_COLORS = {
    'Very Weak': '91',
    'Weak': '31',
    'Fair': '33',
    'Strong': '32',
    'Very Strong': '92',
}


def analyze_characters(password):
    return {
        'length': len(password),
        'uppercase': sum(1 for c in password if c.isupper()),
        'lowercase': sum(1 for c in password if c.islower()),
        'digits': sum(1 for c in password if c.isdigit()),
        'special': sum(1 for c in password if not c.isalnum()),
        'has_upper': any(c.isupper() for c in password),
        'has_lower': any(c.islower() for c in password),
        'has_digit': any(c.isdigit() for c in password),
        'has_special': any((not c.isalnum()) for c in password),
        'unique_count': len(set(password)),
    }


def estimate_pool_size(password):
    pool = 0
    chars = analyze_characters(password)
    if chars['has_lower']:
        pool += 26
    if chars['has_upper']:
        pool += 26
    if chars['has_digit']:
        pool += 10
    if chars['has_special']:
        pool += 32
    return pool


def calculate_entropy(password):
    if not password:
        return 0.0, 0
    pool = estimate_pool_size(password)
    if pool <= 0:
        return 0.0, 0
    return len(password) * math.log2(pool), pool


def detect_repeated(password):
    if not password:
        return False
    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            return True
    counts = Counter(password)
    most = counts.most_common(1)[0][1]
    if len(password) >= 4 and (most / len(password)) > 0.4:
        return True
    return False


def detect_sequential(password):
    if not password or len(password) < 3:
        return False
    pw = password.lower()
    for seq in ('abcdefghijklmnopqrstuvwxyz', '0123456789'):
        for i in range(len(seq) - 2):
            tri = seq[i:i + 3]
            if tri in pw or tri[::-1] in pw:
                return True
    for row in ('qwertyuiop', 'asdfghjkl', 'zxcvbnm'):
        for i in range(len(row) - 2):
            tri = row[i:i + 3]
            if tri in pw or tri[::-1] in pw:
                return True
    return False


def normalize_substitutions(text):
    return ''.join(SUBSTITUTIONS.get(c.lower(), c.lower()) for c in text)


def detect_substitutions(password):
    if not password:
        return False
    norm = normalize_substitutions(password)
    low = password.lower()
    if norm != low and norm in COMMON_BASE_WORDS:
        return True
    for word in COMMON_BASE_WORDS:
        if word in norm and word not in low:
            return True
    return False


def detect_predictable_words(password):
    if not password:
        return []
    low = password.lower()
    return sorted({w for w in COMMON_BASE_WORDS if w in low})


def detect_patterns(password):
    return {
        'repeated': detect_repeated(password),
        'sequential': detect_sequential(password),
        'substitutions': detect_substitutions(password),
        'predictable_words': detect_predictable_words(password),
    }


def load_wordlist(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            return {line.strip().lower() for line in fh if line.strip()}
    except OSError:
        return None


def _gather_wordlist_files(path):
    p = Path(path)
    if p.is_dir():
        return sorted([f for f in p.iterdir() if f.is_file()])
    return [p]


def load_wordlists(paths):
    '''Load and merge one or more wordlist files/directories.

    Returns (words_set_or_None, status, message).
    '''
    if isinstance(paths, (str, Path)):
        paths = [paths]
    if not paths:
        paths = [None]
    all_words = set()
    loaded_files = 0
    missing = []
    unreadable = []
    for wp in paths:
        if wp is None:
            candidates = [Path(__file__).resolve().parent / 'wordlist.txt']
        else:
            candidates = _gather_wordlist_files(wp)
        for f in candidates:
            words = load_wordlist(f)
            if words is None:
                if not Path(f).exists():
                    missing.append(str(f))
                else:
                    unreadable.append(str(f))
            else:
                all_words |= words
                loaded_files += 1
    if loaded_files == 0:
        if missing and not unreadable:
            return None, 'missing', 'Wordlist not found: ' + ', '.join(missing)
        return None, 'unreadable', 'Could not read wordlist: ' + ', '.join(unreadable + missing)
    msg = 'Loaded {} entries from {} file(s).'.format(len(all_words), loaded_files)
    return all_words, 'loaded', msg


def check_common_password(password, wordlist_paths):
    words, status, msg = load_wordlists(wordlist_paths)
    if words is None:
        return False, status, msg
    matched = password.strip().lower() in words
    return matched, status, msg


def zxcvbn_analyze(password):
    if not ZXCVBN_AVAILABLE:
        return None
    try:
        return _zxcvbn(password)
    except Exception:
        return None


def heuristic_score(password, entropy, patterns):
    if entropy >= 80:
        s = 4
    elif entropy >= 60:
        s = 3
    elif entropy >= 40:
        s = 2
    elif entropy >= 20:
        s = 1
    else:
        s = 0
    if patterns['repeated'] or patterns['sequential']:
        s = max(0, s - 1)
    return s


def determine_rating(password, zx, common_match, patterns, entropy):
    if not password:
        return 'Very Weak'
    if zx is not None:
        score = zx.get('score', 0)
    else:
        score = heuristic_score(password, entropy, patterns)
    if common_match:
        score = 0
    if len(password) < 6:
        score = 0
    elif len(password) < 8:
        score = min(score, 1)
    if patterns['repeated'] or patterns['sequential']:
        score = max(0, score - 1)
    if patterns['substitutions'] and score > 2:
        score = 2
    ratings = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong']
    score = max(0, min(4, score))
    return ratings[score]


def build_reasons(password, chars, entropy, pool, common_match, wl_status, wl_msg, patterns, zx):
    reasons = []
    if common_match:
        reasons.append('Password appears in the local common-password wordlist.')
    if len(password) < 8:
        reasons.append('Password is shorter than 8 characters.')
    if not chars['has_upper']:
        reasons.append('No uppercase letters.')
    if not chars['has_lower']:
        reasons.append('No lowercase letters.')
    if not chars['has_digit']:
        reasons.append('No digits.')
    if not chars['has_special']:
        reasons.append('No special characters.')
    if patterns['repeated']:
        reasons.append('Repeated characters detected.')
    if patterns['sequential']:
        reasons.append('Sequential or keyboard pattern detected.')
    if patterns['substitutions']:
        reasons.append('Common character substitutions (leet speak) detected.')
    if patterns['predictable_words']:
        reasons.append('Contains predictable/common words: ' + ', '.join(patterns['predictable_words']))
    if wl_status != 'loaded':
        reasons.append('Wordlist unavailable: ' + wl_msg)
    if zx is not None:
        warning = zx.get('feedback', {}).get('warning')
        if warning:
            reasons.append('zxcvbn: ' + warning)
        for s in zx.get('feedback', {}).get('suggestions', []):
            reasons.append('zxcvbn suggestion: ' + s)
    if not reasons:
        reasons.append('No obvious weaknesses detected by heuristics.')
    return reasons


def build_recommendations(password, chars, common_match, patterns):
    recs = []
    if common_match or patterns['predictable_words']:
        recs.append('Avoid common passwords and personal information.')
    if len(password) < 12:
        recs.append('Use a longer password or passphrase (12+ characters).')
    if chars['unique_count'] < max(1, len(password) // 2):
        recs.append('Avoid repeated characters.')
    if patterns['sequential']:
        recs.append('Avoid sequential or keyboard patterns.')
    if patterns['substitutions']:
        recs.append('Avoid common substitutions like @ for a.')
    if not (chars['has_upper'] and chars['has_lower'] and chars['has_digit'] and chars['has_special']):
        recs.append('Include a mix of uppercase, lowercase, numbers, and symbols.')
    recs.append('Do not reuse passwords across accounts.')
    if len(recs) == 1:
        recs.append('Good password; consider using a password manager.')
    return recs


def analyze(password, wordlist_paths):
    chars = analyze_characters(password)
    entropy, pool = calculate_entropy(password)
    common_match, wl_status, wl_msg = check_common_password(password, wordlist_paths)
    patterns = detect_patterns(password)
    zx = zxcvbn_analyze(password)
    rating = determine_rating(password, zx, common_match, patterns, entropy)
    reasons = build_reasons(password, chars, entropy, pool, common_match, wl_status, wl_msg, patterns, zx)
    recs = build_recommendations(password, chars, common_match, patterns)
    crack_time = ''
    if zx is not None:
        crack_time = zx.get('crack_times_display', {}).get('offline_slow_hashing_1e4_per_second', '')
    zx_score = zx.get('score') if zx is not None else None
    return {
        'password': password,
        'chars': chars,
        'entropy': entropy,
        'pool': pool,
        'common_match': common_match,
        'wl_status': wl_status,
        'wl_msg': wl_msg,
        'patterns': patterns,
        'zx': zx,
        'zx_score': zx_score,
        'crack_time': crack_time,
        'rating': rating,
        'reasons': reasons,
        'recommendations': recs,
    }


def print_report(result, use_color):
    r = result
    chars = r['chars']
    print('')
    print(colorize('Summary', '1', use_color))
    print('-' * 40)
    rating_colored = colorize(r['rating'], RATING_COLORS.get(r['rating'], '0'), use_color)
    print('Strength rating : ' + rating_colored)
    print('Password length : ' + str(chars['length']))
    print('Unique chars    : ' + str(chars['unique_count']))
    print('')
    print(colorize('Character composition', '1', use_color))
    print('-' * 40)
    print('Uppercase : ' + str(chars['uppercase']) + (' (yes)' if chars['has_upper'] else ' (no)'))
    print('Lowercase : ' + str(chars['lowercase']) + (' (yes)' if chars['has_lower'] else ' (no)'))
    print('Digits    : ' + str(chars['digits']) + (' (yes)' if chars['has_digit'] else ' (no)'))
    print('Special   : ' + str(chars['special']) + (' (yes)' if chars['has_special'] else ' (no)'))
    print('')
    print(colorize('Entropy', '1', use_color))
    print('-' * 40)
    print('Assumed pool size R : ' + str(r['pool']))
    print('Theoretical entropy  : {:.2f} bits'.format(r['entropy']))
    print('Formula: H = L x log2(R)')
    print('Assumptions: pool size derived from character categories present.')
    print('Theoretical entropy ignores real-world guessability and patterns.')
    print('')
    print(colorize('Common password check', '1', use_color))
    print('-' * 40)
    if r['common_match']:
        print(colorize('MATCH FOUND: password is in the common-password wordlist.', '91', use_color))
    else:
        if r['wl_status'] == 'loaded':
            print('No match found in wordlist.')
        else:
            print(colorize(r['wl_msg'], '33', use_color))
    print(r['wl_msg'])
    print('')
    print(colorize('Pattern analysis', '1', use_color))
    print('-' * 40)
    p = r['patterns']
    print('Repeated characters : ' + ('yes' if p['repeated'] else 'no'))
    print('Sequential pattern  : ' + ('yes' if p['sequential'] else 'no'))
    print('Substitutions (leet): ' + ('yes' if p['substitutions'] else 'no'))
    if p['predictable_words']:
        print('Predictable words   : ' + ', '.join(p['predictable_words']))
    else:
        print('Predictable words   : none')
    print('')
    if r['zx'] is not None:
        print(colorize('zxcvbn estimate', '1', use_color))
        print('-' * 40)
        print('Score (0-4)        : ' + str(r['zx_score']))
        print('Crack time (slow)  : ' + (r['crack_time'] or 'n/a'))
        print('')
    print(colorize('Reasons for rating', '1', use_color))
    print('-' * 40)
    for reason in r['reasons']:
        print(' - ' + reason)
    print('')
    print(colorize('Recommendations', '1', use_color))
    print('-' * 40)
    for rec in r['recommendations']:
        print(' - ' + rec)
    print('')
    print(colorize('Assumptions note', '1', use_color))
    print('-' * 40)
    print('Theoretical entropy assumes each character is chosen uniformly')
    print('from the pool. Real passwords are not uniform; zxcvbn estimates')
    print('actual guessability including patterns and common words.')
    print('=' * 60)


def read_password(args):
    if args.stdin:
        try:
            line = sys.stdin.readline()
        except Exception:
            return None
        if line == '':
            return ''
        if line.endswith(chr(10)):
            line = line[:-1]
        if line.endswith(chr(13)):
            line = line[:-1]
        return line
    try:
        return getpass.getpass('Enter password to analyze: ')
    except (EOFError, KeyboardInterrupt):
        return None
    except Exception:
        try:
            line = sys.stdin.readline()
        except Exception:
            return None
        if line == '':
            return ''
        if line.endswith(chr(10)):
            line = line[:-1]
        if line.endswith(chr(13)):
            line = line[:-1]
        return line


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='password-analyzer',
        description='Evaluate password strength, entropy, and common-password status.')
    parser.add_argument('--version', action='version',
                        version=APP_TITLE + ' ' + __version__)
    parser.add_argument('--wordlist', '-w', action='append', default=None,
                        help='Path to a custom wordlist file or directory (repeatable)')
    parser.add_argument('--stdin', action='store_true',
                        help='Read password from stdin instead of prompt')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    args = parser.parse_args(argv)

    use_color = (not args.no_color) and supports_color(sys.stdout)

    print(colorize(APP_TITLE, '1', use_color) + '  v' + __version__)
    print('=' * 60)

    # Interactive wordlist selection (so users can scan other wordlists by path).
    if not args.stdin and args.wordlist is None:
        try:
            wl = input('Wordlist path (Enter for default built-in): ').strip()
        except EOFError:
            wl = ''
        if wl:
            args.wordlist = [wl]

    password = read_password(args)
    if password is None:
        print('No password provided.', file=sys.stderr)
        sys.exit(1)

    result = analyze(password, args.wordlist)
    print_report(result, use_color)


if __name__ == '__main__':
    main()
