from dataclasses import dataclass
from typing import List
import os, re, hashlib
from pathlib import Path
from datetime import datetime
from config import logger

@dataclass
class FileAnalysisResult:
    """Result of file analysis"""
    filepath: str
    filename: str
    size: int
    modified_time: str
    decision: str  # 'delete', 'keep', 'ambiguous'
    confidence: float
    language: str  # 'python', 'matlab', 'perl', 'none'
    method: str  # 'pattern-based', 'extension', 'binary-filter'
    reason: str
    file_hash: str


class PatternBasedDetector:
    """Pattern-based code detection engine"""
    
    # Language-specific regex patterns
    PATTERNS = {'python': [('def\\s+\\w+\\s*\\([^)]*\\)\\s*:', 'function definition'),
                ('class\\s+\\w+\\s*(\\([^)]*\\))?\\s*:', 'class definition'),
                ('import\\s+[\\w.]+', 'import statement'),
                ('from\\s+[\\w.]+\\s+import', 'from-import statement'),
                ('if\\s+__name__\\s*==\\s*["\\\']__main__["\\\']', 'main guard'),
                ('@\\w+', 'decorator'),
                ('(print|input)\\s*\\(', 'built-in function'),
                ('#\\s*.*\\n', 'python comment'),
                ('"""[\\s\\S]*?"""|\\\'\\\'\\\'[\\s\\S]*?\\\'\\\'\\\'', 'docstring')],
     'matlab': [('function\\s+.*=.*\\([^)]*\\)', 'function definition'),
                ('\\bend\\b', 'end keyword'),
                ('%[^\\n]*', 'matlab comment'),
                ('fprintf\\s*\\(', 'fprintf call'),
                ('disp\\s*\\(', 'disp call'),
                ('plot\\s*\\(', 'plot call'),
                ('clc\\s*;?', 'clear command'),
                ('clear\\s+(all|variables)?', 'clear command'),
                ('figure\\s*(\\(\\d+\\))?', 'figure command')],
     'perl': [('sub\\s+\\w+\\s*\\{', 'subroutine definition'),
              ('my\\s+[\\$@%]\\w+', 'my declaration'),
              ('use\\s+strict', 'strict pragma'),
              ('use\\s+warnings', 'warnings pragma'),
              ('print\\s+', 'print statement'),
              ('->\\s*\\{', 'arrow operator'),
              ('#[^\\n]*', 'perl comment'),
              ('\\$\\w+|\\@\\w+|\\%\\w+', 'perl variable')],
     'java': [('public\\s+class\\s+\\w+', 'class definition'),
              ('private\\s+class\\s+\\w+', 'class definition'),
              ('public\\s+static\\s+void\\s+main', 'main method'),
              ('public\\s+\\w+\\s+\\w+\\s*\\([^)]*\\)', 'method definition'),
              ('private\\s+\\w+\\s+\\w+\\s*\\([^)]*\\)', 'method definition'),
              ('import\\s+[\\w.]+;', 'import statement'),
              ('package\\s+[\\w.]+;', 'package statement'),
              ('new\\s+\\w+\\s*\\(', 'object creation'),
              ('@Override', 'annotation'),
              ('System\\.out\\.print', 'print statement'),
              ('//[^\\n]*', 'single-line comment'),
              ('/\\*[\\s\\S]*?\\*/', 'multi-line comment')],
     'javascript': [('function\\s+\\w+\\s*\\([^)]*\\)', 'function definition'),
                    ('const\\s+\\w+\\s*=\\s*\\([^)]*\\)\\s*=>', 'arrow function'),
                    ('let\\s+\\w+\\s*=\\s*function', 'function expression'),
                    ('var\\s+\\w+\\s*=\\s*function', 'function expression'),
                    ('class\\s+\\w+', 'class definition'),
                    ('import\\s+.*\\s+from\\s+["\\\']', 'import statement'),
                    ('require\\s*\\(["\\\']', 'require statement'),
                    ('export\\s+(default|const|function|class)', 'export statement'),
                    ('console\\.log\\s*\\(', 'console log'),
                    ('=>\\s*\\{', 'arrow function'),
                    ('//[^\\n]*', 'single-line comment'),
                    ('/\\*[\\s\\S]*?\\*/', 'multi-line comment'),
                    ('document\\.(getElementById|querySelector)', 'DOM manipulation')],
     'html': [('<!DOCTYPE\\s+html>', 'doctype declaration'),
              ('<html[^>]*>', 'html tag'),
              ('<head[^>]*>', 'head tag'),
              ('<body[^>]*>', 'body tag'),
              ('<div[^>]*>', 'div tag'),
              ('<script[^>]*>', 'script tag'),
              ('<style[^>]*>', 'style tag'),
              ('<link[^>]*>', 'link tag'),
              ('<meta[^>]*>', 'meta tag'),
              ('<form[^>]*>', 'form tag'),
              ('<input[^>]*>', 'input tag'),
              ('<button[^>]*>', 'button tag'),
              ('<!--[\\s\\S]*?-->', 'html comment')],
     'css': [('\\.\\w+\\s*\\{', 'class selector'),
             ('#\\w+\\s*\\{', 'id selector'),
             ('\\w+\\s*\\{', 'element selector'),
             ('@media\\s+', 'media query'),
             ('@import\\s+', 'import statement'),
             ('@keyframes\\s+\\w+', 'keyframes animation'),
             (':\\w+\\s*\\{', 'pseudo-class'),
             ('::\\w+\\s*\\{', 'pseudo-element'),
             ('(color|background|font|margin|padding|width|height):', 'property'),
             ('/\\*[\\s\\S]*?\\*/', 'css comment'),
             ('rgba?\\s*\\(', 'color function')],
     'ruby': [('^\\s*def\\s+\\w+[!?=]?\\s*(\\([^)]*\\))?', 'method definition'),
              ('^\\s*class\\s+\\w+', 'class definition'),
              ('^\\s*module\\s+\\w+', 'module definition'),
              ('^\\s*require\\s+[\'"][^\'"]+[\'"]', 'require statement'),
              ('^\\s*puts\\s+.+', 'puts statement')]}
    
    # Language-specific keywords
    KEYWORDS = {'python': ['def',
                'class',
                'import',
                'from',
                'if',
                'else',
                'elif',
                'for',
                'while',
                'try',
                'except',
                'finally',
                'with',
                'return',
                'yield',
                'lambda',
                'pass',
                'break',
                'continue',
                'True',
                'False',
                'None',
                'and',
                'or',
                'not',
                'in',
                'is'],
     'matlab': ['function',
                'end',
                'if',
                'else',
                'elseif',
                'for',
                'while',
                'return',
                'fprintf',
                'disp',
                'plot',
                'figure',
                'hold',
                'clc',
                'clear',
                'load',
                'save',
                'input'],
     'perl': ['sub',
              'my',
              'our',
              'use',
              'require',
              'if',
              'else',
              'elsif',
              'for',
              'foreach',
              'while',
              'until',
              'return',
              'print',
              'chomp',
              'split',
              'join',
              'push',
              'pop',
              'shift'],
     'java': ['public',
              'private',
              'protected',
              'class',
              'interface',
              'extends',
              'implements',
              'void',
              'int',
              'String',
              'boolean',
              'double',
              'if',
              'else',
              'for',
              'while',
              'switch',
              'case',
              'return',
              'new',
              'this',
              'super',
              'static',
              'final',
              'abstract',
              'try',
              'catch',
              'throw',
              'throws',
              'import',
              'package'],
     'javascript': ['function',
                    'const',
                    'let',
                    'var',
                    'if',
                    'else',
                    'for',
                    'while',
                    'return',
                    'class',
                    'this',
                    'new',
                    'async',
                    'await',
                    'import',
                    'export',
                    'require',
                    'default',
                    'switch',
                    'case',
                    'break',
                    'continue',
                    'try',
                    'catch',
                    'throw',
                    'typeof',
                    'null',
                    'undefined',
                    'true',
                    'false',
                    'console'],
     'html': ['html',
              'head',
              'body',
              'div',
              'span',
              'script',
              'style',
              'link',
              'meta',
              'title',
              'form',
              'input',
              'button',
              'img',
              'a',
              'p',
              'h1',
              'h2',
              'h3',
              'ul',
              'li',
              'table',
              'DOCTYPE'],
     'css': ['color',
             'background',
             'font',
             'margin',
             'padding',
             'width',
             'height',
             'display',
             'position',
             'flex',
             'grid',
             'border',
             'hover',
             'active',
             'focus',
             'media',
             'import',
             'keyframes',
             'transform',
             'transition',
             'animation',
             'rgba',
             'px',
             'rem'],
     'ruby': ['def', 'end', 'class', 'module', 'require', 'puts', 'attr_accessor', 'initialize']}
    
    # Common file extensions
    EXTENSIONS = {'python': ['.py', '.pyw', '.pyc', '.pyo'],
     'matlab': ['.m', '.mat', '.fig'],
     'perl': ['.pl', '.pm', '.t'],
     'java': ['.java', '.class', '.jar'],
     'javascript': ['.js', '.jsx', '.mjs', '.cjs'],
     'html': ['.html', '.htm'],
     'css': ['.css', '.scss', '.sass', '.less'],
     'ruby': ['.rb', '.rake', '.gemspec']}

    # Language-unique syntax indicators that are hard to fake accidentally.
    SIGNATURE_PATTERNS = {'python': ['^\\s*def\\s+\\w+\\s*\\([^)]*\\)\\s*:',
                '^\\s*from\\s+[\\w.]+\\s+import\\s+[\\w.*,\\s]+',
                'if\\s+__name__\\s*==\\s*["\\\']__main__["\\\']',
                '^\\s*except(\\s+\\w+(\\s+as\\s+\\w+)?)?\\s*:'],
     'matlab': ['^\\s*function\\s+(\\[[^\\]]+\\]|\\w+)\\s*=\\s*\\w+\\s*\\(',
                '^\\s*end\\s*$',
                '^\\s*clc\\s*;?\\s*$'],
     'perl': ['^\\s*use\\s+strict\\s*;', '^\\s*my\\s+[\\$@%]\\w+', '^\\s*sub\\s+\\w+\\s*\\{'],
     'java': ['public\\s+static\\s+void\\s+main\\s*\\(',
              '^\\s*package\\s+[\\w.]+\\s*;',
              '^\\s*import\\s+[\\w.]+\\s*;',
              '^\\s*(public|private|protected)\\s+class\\s+\\w+\\s*\\{',
              'System\\.out\\.(print|println)\\s*\\('],
     'javascript': ['^\\s*(const|let|var)\\s+\\w+\\s*=',
                    '^\\s*import\\s+.+\\s+from\\s+["\\\']',
                    '=>\\s*\\{',
                    'console\\.log\\s*\\('],
     'html': ['<!DOCTYPE\\s+html>', '<html[^>]*>', '<body[^>]*>'],
     'css': ['^\\s*[\\.\\#]?\\w[\\w\\-]*\\s*\\{', '^\\s*@media\\s+', '^\\s*[\\w\\-]+\\s*:\\s*[^;]+;'],
     'ruby': ['^\\s*def\\s+\\w+[!?=]?', '^\\s*class\\s+\\w+', '^\\s*module\\s+\\w+']}

    # Control-flow tokens are shared by many languages and should have low influence.
    COMMON_KEYWORDS = {
        'if', 'else', 'for', 'while', 'return', 'try', 'catch', 'case',
        'switch', 'break', 'continue', 'class', 'import'
    }
    
    @staticmethod
    def _pattern_weight(description: str) -> float:
        """Return score weight for a matched pattern."""
        desc = description.lower()
        if 'comment' in desc:
            return 0.4
        if 'function' in desc or 'class' in desc or 'main' in desc:
            return 2.2
        if 'import' in desc or 'package' in desc or 'annotation' in desc:
            return 1.8
        return 1.2

    @staticmethod
    def _keyword_weight(keyword: str) -> float:
        """Lower weight for cross-language keywords to reduce false positives."""
        return 0.25 if keyword in PatternBasedDetector.COMMON_KEYWORDS else 1.0

    @staticmethod
    def is_binary(filepath: str, sample_size: int = 8192) -> bool:
        """Check if file is binary"""
        try:
            with open(filepath, 'rb') as f:
                chunk = f.read(sample_size)
                # Check for null bytes and other binary indicators
                if b'\x00' in chunk:
                    return True
                # Check for high ratio of non-text characters
                text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
                non_text = sum(1 for byte in chunk if byte not in text_chars)
                return non_text / len(chunk) > 0.3 if chunk else False
        except Exception as e:
            logger.warning(f"Error checking binary status for {filepath}: {e}")
            return True
    
    @staticmethod
    def analyze_file(filepath: str) -> FileAnalysisResult:
        """Analyze a file and determine if it contains code"""
        try:
            filename = os.path.basename(filepath)
            stat_info = os.stat(filepath)
            file_size = stat_info.st_size
            modified_time = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            
            # Calculate file hash
            file_hash = PatternBasedDetector._calculate_hash(filepath)
            
            # Step 1: Check if binary
            if PatternBasedDetector.is_binary(filepath):
                return FileAnalysisResult(
                    filepath=filepath,
                    filename=filename,
                    size=file_size,
                    modified_time=modified_time,
                    decision='keep',
                    confidence=1.0,
                    language='none',
                    method='binary-filter',
                    reason='Binary file, not code',
                    file_hash=file_hash
                )
            
            # Step 2: Check file extension
            ext = Path(filepath).suffix.lower()
            extension_lang = None
            for lang, exts in PatternBasedDetector.EXTENSIONS.items():
                if ext in exts:
                    extension_lang = lang
                    break
            
            # Step 3: Read file content
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(50000)  # Read first 50KB
            except Exception as e:
                logger.warning(f"Error reading {filepath}: {e}")
                return FileAnalysisResult(
                    filepath=filepath,
                    filename=filename,
                    size=file_size,
                    modified_time=modified_time,
                    decision='keep',
                    confidence=0.5,
                    language='none',
                    method='error',
                    reason=f'Error reading file: {str(e)}',
                    file_hash=file_hash
                )
            
            # Step 4: Pattern-based analysis
            scores = {}
            pattern_matches = {}
            
            for lang, patterns in PatternBasedDetector.PATTERNS.items():
                score = 0
                matches = []
                
                # Check patterns
                for pattern, description in patterns:
                    found = re.findall(pattern, content, re.MULTILINE)
                    if found:
                        score += len(found) * PatternBasedDetector._pattern_weight(description)
                        matches.append(f"{description} ({len(found)}x)")
                
                # Check keywords
                for keyword in PatternBasedDetector.KEYWORDS[lang]:
                    regex = re.compile(r'\b' + re.escape(keyword) + r'\b')
                    found = regex.findall(content)
                    if found:
                        score += min(len(found), 8) * PatternBasedDetector._keyword_weight(keyword)

                # Strong language-unique signatures.
                signature_hits = 0
                for sig_pattern in PatternBasedDetector.SIGNATURE_PATTERNS.get(lang, []):
                    if re.search(sig_pattern, content, re.MULTILINE):
                        signature_hits += 1
                score += signature_hits * 4
                
                # Bonus for code structure
                if re.search(r'^[ \t]+\w', content, re.MULTILINE):
                    score += 3  # Indented code
                if re.search(r'[\{\}\[\]\(\)]', content):
                    score += 2  # Brackets/braces
                
                scores[lang] = score
                pattern_matches[lang] = matches
            
            # Determine language and confidence
            if not scores or max(scores.values()) == 0:
                detected_lang = 'none'
                max_score = 0
            else:
                detected_lang = max(scores, key=scores.get)
                max_score = scores[detected_lang]
            
            sorted_scores = sorted(scores.items(), key=lambda item: item[1], reverse=True)
            second_best_score = sorted_scores[1][1] if len(sorted_scores) > 1 else 0
            score_margin = max_score - second_best_score

            # Confidence combines absolute evidence and separation from the next-best language.
            confidence = min(1.0, ((max_score / 40.0) * 0.7) + ((score_margin / 20.0) * 0.3))
            
            # Small confidence boost for matching extension (weak signal only).
            if extension_lang == detected_lang:
                confidence = min(confidence + 0.08, 1.0)
            
            # Make decision
            if confidence > 0.78 and score_margin >= 4:
                decision = 'delete'
                reason = f"High confidence {detected_lang} code: {', '.join(pattern_matches[detected_lang][:3])}"
            elif confidence < 0.25:
                decision = 'keep'
                reason = f"Low confidence, no significant code patterns (score: {max_score})"
            else:
                decision = 'ambiguous'
                reason = f"Medium confidence {detected_lang} code (score: {max_score}), needs LLM verification"
            
            return FileAnalysisResult(
                filepath=filepath,
                filename=filename,
                size=file_size,
                modified_time=modified_time,
                decision=decision,
                confidence=confidence,
                language=detected_lang,
                method='pattern-based',
                reason=reason,
                file_hash=file_hash
            )
            
        except Exception as e:
            logger.error(f"Error analyzing {filepath}: {e}")
            return FileAnalysisResult(
                filepath=filepath,
                filename=os.path.basename(filepath),
                size=0,
                modified_time='',
                decision='keep',
                confidence=0.0,
                language='none',
                method='error',
                reason=f'Analysis error: {str(e)}',
                file_hash=''
            )


    @staticmethod
    def _calculate_hash(filepath: str) -> str:
        """Calculate SHA-256 hash of file"""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return ''
