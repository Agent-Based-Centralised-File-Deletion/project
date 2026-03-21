from dataclasses import dataclass
from typing import Any, Dict, List
from copy import deepcopy
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
    PATTERNS = {
        'python': [
            (r'def\s+\w+\s*\([^)]*\)\s*:', 'function definition'),
            (r'class\s+\w+\s*(\([^)]*\))?\s*:', 'class definition'),
            (r'import\s+[\w.]+', 'import statement'),
            (r'from\s+[\w.]+\s+import', 'from-import statement'),
            (r'if\s+__name__\s*==\s*["\']__main__["\']', 'main guard'),
            (r'@\w+', 'decorator'),
            (r'(print|input)\s*\(', 'built-in function'),
            (r'#\s*.*\n', 'python comment'),
            (r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'', 'docstring'),
        ],
        'matlab': [
            (r'function\s+.*=.*\([^)]*\)', 'function definition'),
            (r'\bend\b', 'end keyword'),
            (r'%[^\n]*', 'matlab comment'),
            (r'fprintf\s*\(', 'fprintf call'),
            (r'disp\s*\(', 'disp call'),
            (r'plot\s*\(', 'plot call'),
            (r'clc\s*;?', 'clear command'),
            (r'clear\s+(all|variables)?', 'clear command'),
            (r'figure\s*(\(\d+\))?', 'figure command'),
        ],
        'perl': [
            (r'sub\s+\w+\s*\{', 'subroutine definition'),
            (r'my\s+[\$@%]\w+', 'my declaration'),
            (r'use\s+strict', 'strict pragma'),
            (r'use\s+warnings', 'warnings pragma'),
            (r'print\s+', 'print statement'),
            (r'->\s*\{', 'arrow operator'),
            (r'#[^\n]*', 'perl comment'),
            (r'\$\w+|\@\w+|\%\w+', 'perl variable'),
        ],
        'java': [
            (r'public\s+class\s+\w+', 'class definition'),
            (r'private\s+class\s+\w+', 'class definition'),
            (r'public\s+static\s+void\s+main', 'main method'),
            (r'public\s+\w+\s+\w+\s*\([^)]*\)', 'method definition'),
            (r'private\s+\w+\s+\w+\s*\([^)]*\)', 'method definition'),
            (r'import\s+[\w.]+;', 'import statement'),
            (r'package\s+[\w.]+;', 'package statement'),
            (r'new\s+\w+\s*\(', 'object creation'),
            (r'@Override', 'annotation'),
            (r'System\.out\.print', 'print statement'),
            (r'//[^\n]*', 'single-line comment'),
            (r'/\*[\s\S]*?\*/', 'multi-line comment'),
        ],
        'c': [
            (r'#include\s*<[^>]+>', 'include directive'),
            (r'\b(int|char|float|double|void)\s+\*?\s*\w+\s*\([^)]*\)\s*\{', 'function definition'),
            (r'\bprintf\s*\(', 'printf call'),
            (r'\bscanf\s*\(', 'scanf call'),
            (r'\b(sizeof|malloc|free)\b', 'memory keyword'),
            (r'//[^\n]*', 'single-line comment'),
            (r'/\*[\s\S]*?\*/', 'multi-line comment'),
        ],
        'cpp': [
            (r'#include\s*<[^>]+>', 'include directive'),
            (r'\bstd::\w+', 'std namespace usage'),
            (r'\bclass\s+\w+\s*\{', 'class definition'),
            (r'\btemplate\s*<[^>]+>', 'template definition'),
            (r'\b(cout|cin)\s*<<|\b(cout|cin)\s*>>', 'stream operator'),
            (r'\bnamespace\s+\w+', 'namespace declaration'),
            (r'//[^\n]*', 'single-line comment'),
            (r'/\*[\s\S]*?\*/', 'multi-line comment'),
        ],
        'php': [
            (r'<\?php', 'php open tag'),
            (r'\$\w+\s*=', 'php variable assignment'),
            (r'function\s+\w+\s*\([^)]*\)\s*\{', 'function definition'),
            (r'(echo|print)\s+', 'output statement'),
            (r'->\w+', 'object operator'),
            (r'\brequire(_once)?\s*\(|\binclude(_once)?\s*\(', 'include/require'),
            (r'//[^\n]*|#[^\n]*', 'single-line comment'),
        ],
        'javascript': [
            (r'function\s+\w+\s*\([^)]*\)', 'function definition'),
            (r'const\s+\w+\s*=\s*\([^)]*\)\s*=>', 'arrow function'),
            (r'let\s+\w+\s*=\s*function', 'function expression'),
            (r'var\s+\w+\s*=\s*function', 'function expression'),
            (r'class\s+\w+', 'class definition'),
            (r'import\s+.*\s+from\s+["\']', 'import statement'),
            (r'require\s*\(["\']', 'require statement'),
            (r'export\s+(default|const|function|class)', 'export statement'),
            (r'console\.log\s*\(', 'console log'),
            (r'=>\s*\{', 'arrow function'),
            (r'//[^\n]*', 'single-line comment'),
            (r'/\*[\s\S]*?\*/', 'multi-line comment'),
            (r'document\.(getElementById|querySelector)', 'DOM manipulation'),
        ],
        'html': [
            (r'<!DOCTYPE\s+html>', 'doctype declaration'),
            (r'<html[^>]*>', 'html tag'),
            (r'<head[^>]*>', 'head tag'),
            (r'<body[^>]*>', 'body tag'),
            (r'<div[^>]*>', 'div tag'),
            (r'<script[^>]*>', 'script tag'),
            (r'<style[^>]*>', 'style tag'),
            (r'<link[^>]*>', 'link tag'),
            (r'<meta[^>]*>', 'meta tag'),
            (r'<form[^>]*>', 'form tag'),
            (r'<input[^>]*>', 'input tag'),
            (r'<button[^>]*>', 'button tag'),
            (r'<!--[\s\S]*?-->', 'html comment'),
        ],
        'css': [
            (r'\.\w+\s*\{', 'class selector'),
            (r'#\w+\s*\{', 'id selector'),
            (r'\w+\s*\{', 'element selector'),
            (r'@media\s+', 'media query'),
            (r'@import\s+', 'import statement'),
            (r'@keyframes\s+\w+', 'keyframes animation'),
            (r':\w+\s*\{', 'pseudo-class'),
            (r'::\w+\s*\{', 'pseudo-element'),
            (r'(color|background|font|margin|padding|width|height):', 'property'),
            (r'/\*[\s\S]*?\*/', 'css comment'),
            (r'rgba?\s*\(', 'color function'),
        ],
        'mysql': [
            (r'\bCREATE\s+TABLE\b', 'create table'),
            (r'\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]*?\b(FROM|INTO)\b', 'dml statement'),
            (r'\bALTER\s+TABLE\b', 'alter table'),
            (r'\bJOIN\b', 'join clause'),
            (r'\bWHERE\b', 'where clause'),
            (r'--[^\n]*', 'sql comment'),
        ],
        'nosql': [
            (r'\bdb\.\w+\.(find|insertOne|insertMany|updateOne|updateMany|aggregate)\s*\(', 'mongodb operation'),
            (r'"\$(set|inc|push|pull|match|group|project)"', 'mongodb operator'),
            (r'\b(CREATE\s+KEYSPACE|CREATE\s+COLUMNFAMILY|SELECT\s+JSON)\b', 'cassandra/cql syntax'),
            (r'\{[\s\S]*:\s*[\s\S]*\}', 'json document'),
        ],
        'prolog': [
            (r'^\s*\w+\s*\([^)]*\)\s*:-', 'rule definition'),
            (r'^\s*\w+\s*\([^)]*\)\s*\.', 'fact definition'),
            (r'^\s*:-\s*\w+', 'directive'),
            (r'^\s*\?-', 'query'),
            (r'%[^\n]*', 'prolog comment'),
        ],
        'assembly': [
            (r'^\s*(MOV|ADD|SUB|CMP|JMP|CALL|PUSH|POP)\b', 'instruction mnemonic'),
            (r'^\s*(section|segment)\s+\.\w+', 'section declaration'),
            (r'^\s*global\s+\w+', 'global symbol'),
            (r'^\s*\w+:\s*$', 'label'),
            (r';[^\n]*', 'assembly comment'),
        ]
    }
    
    # Language-specific keywords
    KEYWORDS = {
        'python': [
            'def', 'class', 'import', 'from', 'if', 'else', 'elif',
            'for', 'while', 'try', 'except', 'finally', 'with',
            'return', 'yield', 'lambda', 'pass', 'break', 'continue',
            'True', 'False', 'None', 'and', 'or', 'not', 'in', 'is'
        ],
        'matlab': [
            'function', 'end', 'if', 'else', 'elseif', 'for', 'while',
            'return', 'fprintf', 'disp', 'plot', 'figure', 'hold',
            'clc', 'clear', 'load', 'save', 'input'
        ],
        'perl': [
            'sub', 'my', 'our', 'use', 'require', 'if', 'else', 'elsif',
            'for', 'foreach', 'while', 'until', 'return', 'print',
            'chomp', 'split', 'join', 'push', 'pop', 'shift'
        ],
        'java': [
            'public', 'private', 'protected', 'class', 'interface', 'extends',
            'implements', 'void', 'int', 'String', 'boolean', 'double',
            'if', 'else', 'for', 'while', 'switch', 'case', 'return',
            'new', 'this', 'super', 'static', 'final', 'abstract',
            'try', 'catch', 'throw', 'throws', 'import', 'package'
        ],
        'c': [
            'int', 'char', 'float', 'double', 'void', 'struct', 'typedef',
            'enum', 'union', 'sizeof', 'malloc', 'free', 'printf', 'scanf',
            '#include', '#define', 'NULL', 'static', 'extern'
        ],
        'cpp': [
            'class', 'namespace', 'template', 'typename', 'std', 'cout', 'cin',
            'vector', 'string', 'new', 'delete', 'public', 'private', 'protected',
            'virtual', 'override', 'constexpr', 'nullptr'
        ],
        'php': [
            'php', 'function', 'echo', 'print', 'array', 'foreach', 'require',
            'include', 'namespace', 'use', 'class', 'public', 'private',
            'protected', 'static', 'null', 'true', 'false'
        ],
        'javascript': [
            'function', 'const', 'let', 'var', 'if', 'else', 'for',
            'while', 'return', 'class', 'this', 'new', 'async', 'await',
            'import', 'export', 'require', 'default', 'switch', 'case',
            'break', 'continue', 'try', 'catch', 'throw', 'typeof',
            'null', 'undefined', 'true', 'false', 'console'
        ],
        'html': [
            'html', 'head', 'body', 'div', 'span', 'script', 'style',
            'link', 'meta', 'title', 'form', 'input', 'button', 'img',
            'a', 'p', 'h1', 'h2', 'h3', 'ul', 'li', 'table', 'DOCTYPE'
        ],
        'css': [
            'color', 'background', 'font', 'margin', 'padding', 'width',
            'height', 'display', 'position', 'flex', 'grid', 'border',
            'hover', 'active', 'focus', 'media', 'import', 'keyframes',
            'transform', 'transition', 'animation', 'rgba', 'px', 'rem'
        ],
        'mysql': [
            'select', 'insert', 'update', 'delete', 'from', 'where', 'join',
            'group', 'order', 'having', 'create', 'table', 'alter', 'index',
            'primary', 'foreign', 'key', 'engine', 'values'
        ],
        'nosql': [
            'db', 'find', 'insertOne', 'insertMany', 'updateOne', 'updateMany',
            'aggregate', '$set', '$inc', '$push', '$pull', '$match', '$group',
            'collection', 'document', 'keyspace', 'columnfamily'
        ],
        'prolog': [
            ':-', '?-', 'is', 'not', 'fail', 'true', 'false', 'assert',
            'retract', 'consult', 'dynamic', 'rule', 'fact'
        ],
        'assembly': [
            'mov', 'add', 'sub', 'mul', 'div', 'cmp', 'jmp', 'je', 'jne',
            'call', 'ret', 'push', 'pop', 'eax', 'ebx', 'ecx', 'edx',
            'section', 'global', 'label'
        ]
    }
    
    # Common file extensions
    EXTENSIONS = {
        'python': ['.py', '.pyw', '.pyc', '.pyo'],
        'matlab': ['.m', '.mat', '.fig'],
        'perl': ['.pl', '.pm', '.t'],
        'java': ['.java', '.class', '.jar'],
        'c': ['.c', '.h'],
        'cpp': ['.cpp', '.cc', '.cxx', '.hpp', '.hh', '.hxx'],
        'php': ['.php', '.phtml', '.php3', '.php4', '.php5'],
        'javascript': ['.js', '.jsx', '.mjs', '.cjs'],
        'html': ['.html', '.htm'],
        'css': ['.css', '.scss', '.sass', '.less'],
        'mysql': ['.sql'],
        'nosql': ['.mongo', '.cql', '.jsonl'],
        'prolog': ['.pro', '.prolog', '.plg'],
        'assembly': ['.asm', '.s', '.S']
    }

    # Language-unique syntax indicators that are hard to fake accidentally.
    SIGNATURE_PATTERNS = {
        'python': [
            r'^\s*def\s+\w+\s*\([^)]*\)\s*:',
            r'^\s*from\s+[\w.]+\s+import\s+[\w.*,\s]+',
            r'if\s+__name__\s*==\s*["\']__main__["\']',
            r'^\s*except(\s+\w+(\s+as\s+\w+)?)?\s*:',
        ],
        'matlab': [
            r'^\s*function\s+(\[[^\]]+\]|\w+)\s*=\s*\w+\s*\(',
            r'^\s*end\s*$',
            r'^\s*clc\s*;?\s*$',
        ],
        'perl': [
            r'^\s*use\s+strict\s*;',
            r'^\s*my\s+[\$@%]\w+',
            r'^\s*sub\s+\w+\s*\{',
        ],
        'java': [
            r'public\s+static\s+void\s+main\s*\(',
            r'^\s*package\s+[\w.]+\s*;',
            r'^\s*import\s+[\w.]+\s*;',
            r'^\s*(public|private|protected)\s+class\s+\w+\s*\{',
            r'System\.out\.(print|println)\s*\(',
        ],
        'c': [
            r'^\s*#include\s*<[^>]+>',
            r'^\s*int\s+main\s*\([^)]*\)\s*\{',
            r'\bprintf\s*\(',
        ],
        'cpp': [
            r'^\s*#include\s*<iostream>',
            r'\bstd::(cout|cin)\b',
            r'^\s*template\s*<[^>]+>',
            r'^\s*class\s+\w+\s*\{',
        ],
        'php': [
            r'<\?php',
            r'^\s*\$\w+\s*=',
            r'\b(require|include)(_once)?\s*\(',
        ],
        'javascript': [
            r'^\s*(const|let|var)\s+\w+\s*=',
            r'^\s*import\s+.+\s+from\s+["\']',
            r'=>\s*\{',
            r'console\.log\s*\(',
        ],
        'html': [
            r'<!DOCTYPE\s+html>',
            r'<html[^>]*>',
            r'<body[^>]*>',
        ],
        'css': [
            r'^\s*[\.\#]?\w[\w\-]*\s*\{',
            r'^\s*@media\s+',
            r'^\s*[\w\-]+\s*:\s*[^;]+;',
        ],
        'mysql': [
            r'\bCREATE\s+TABLE\b',
            r'\bSELECT\b[\s\S]*\bFROM\b',
            r'\bENGINE\s*=\s*\w+',
        ],
        'nosql': [
            r'\bdb\.\w+\.(find|aggregate|updateOne)\s*\(',
            r'"\$(set|inc|match|group)"',
            r'^\s*\{[\s\S]*\}\s*$',
        ],
        'prolog': [
            r'^\s*\w+\s*\([^)]*\)\s*:-',
            r'^\s*\w+\s*\([^)]*\)\s*\.',
            r'^\s*\?-',
        ],
        'assembly': [
            r'^\s*(MOV|ADD|SUB|CMP|JMP|CALL|PUSH|POP)\b',
            r'^\s*section\s+\.\w+',
            r'^\s*\w+:\s*$',
        ]
    }

    # Control-flow tokens are shared by many languages and should have low influence.
    COMMON_KEYWORDS = {
        'if', 'else', 'for', 'while', 'return', 'try', 'catch', 'case',
        'switch', 'break', 'continue', 'class', 'import'
    }

    # Keep immutable built-ins so each task can cleanly rebuild detector maps.
    DEFAULT_PATTERNS = deepcopy(PATTERNS)
    DEFAULT_KEYWORDS = deepcopy(KEYWORDS)
    DEFAULT_EXTENSIONS = deepcopy(EXTENSIONS)
    DEFAULT_SIGNATURE_PATTERNS = deepcopy(SIGNATURE_PATTERNS)

    @classmethod
    def configure_custom_languages(cls, custom_languages: Dict[str, Any]):
        """Merge per-task custom languages into detector maps."""
        cls.PATTERNS = deepcopy(cls.DEFAULT_PATTERNS)
        cls.KEYWORDS = deepcopy(cls.DEFAULT_KEYWORDS)
        cls.EXTENSIONS = deepcopy(cls.DEFAULT_EXTENSIONS)
        cls.SIGNATURE_PATTERNS = deepcopy(cls.DEFAULT_SIGNATURE_PATTERNS)

        if not isinstance(custom_languages, dict):
            return

        for raw_name, raw_spec in custom_languages.items():
            language = str(raw_name).strip().lower()
            spec = raw_spec if isinstance(raw_spec, dict) else {}
            if not language:
                continue

            patterns = []
            for idx, item in enumerate(spec.get('patterns', []) or [], start=1):
                if isinstance(item, dict):
                    regex = str(item.get('regex', '')).strip()
                    description = str(item.get('description', '')).strip() or f'custom pattern {idx}'
                else:
                    regex = str(item).strip()
                    description = f'custom pattern {idx}'
                if not regex:
                    continue
                try:
                    re.compile(regex)
                except re.error:
                    logger.warning("Skipping invalid custom pattern for %s: %s", language, regex)
                    continue
                patterns.append((regex, description))
            if not patterns:
                logger.warning("Skipping custom language %s: no valid patterns", language)
                continue

            signatures = []
            for sig in spec.get('signature_patterns', []) or []:
                regex = str(sig).strip()
                if not regex:
                    continue
                try:
                    re.compile(regex)
                except re.error:
                    logger.warning("Skipping invalid custom signature for %s: %s", language, regex)
                    continue
                signatures.append(regex)

            keywords = [str(k).strip() for k in (spec.get('keywords', []) or []) if str(k).strip()]

            extensions = []
            for ext in (spec.get('extensions', []) or []):
                value = str(ext).strip().lower()
                if not value:
                    continue
                if not value.startswith('.'):
                    value = f'.{value}'
                extensions.append(value)

            cls.PATTERNS[language] = patterns
            cls.KEYWORDS[language] = keywords
            cls.EXTENSIONS[language] = sorted(set(extensions))
            cls.SIGNATURE_PATTERNS[language] = signatures
    
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
                    if re.match(r'^\w+$', keyword):
                        regex = re.compile(r'\b' + re.escape(keyword) + r'\b')
                    else:
                        regex = re.compile(re.escape(keyword))
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

            # C and C++ overlap strongly. If extension says .cpp/.cc/etc and the
            # C++ score is close, prefer reporting C++ for clearer UI output.
            if (
                detected_lang == 'c'
                and extension_lang == 'cpp'
                and scores.get('cpp', 0) > 0
                and (scores.get('c', 0) - scores.get('cpp', 0)) <= 6
            ):
                detected_lang = 'cpp'
                max_score = scores['cpp']

            second_best_score = max(
                (score for lang, score in scores.items() if lang != detected_lang),
                default=0
            )
            score_margin = max(0, max_score - second_best_score)

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
