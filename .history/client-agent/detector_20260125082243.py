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
        ]
    }
    
    # Common file extensions
    EXTENSIONS = {
        'python': ['.py', '.pyw', '.pyc', '.pyo'],
        'matlab': ['.m', '.mat', '.fig'],
        'perl': ['.pl', '.pm', '.t'],
        'java': ['.java', '.class', '.jar'],
        'javascript': ['.js', '.jsx', '.mjs', '.cjs'],
        'html': ['.html', '.htm'],
        'css': ['.css', '.scss', '.sass', '.less']
    }
    
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
                        score += len(found) * 2
                        matches.append(f"{description} ({len(found)}x)")
                
                # Check keywords
                for keyword in PatternBasedDetector.KEYWORDS[lang]:
                    regex = re.compile(r'\b' + re.escape(keyword) + r'\b')
                    found = regex.findall(content)
                    if found:
                        score += len(found)
                
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
            
            # Normalize confidence (0-1 range)
            # Typical code file scores 20-100+, adjust threshold
            confidence = min(max_score / 30.0, 1.0)
            
            # Boost confidence if extension matches
            if extension_lang == detected_lang:
                confidence = min(confidence * 1.3, 1.0)
            
            # Make decision
            if confidence > 0.75:
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