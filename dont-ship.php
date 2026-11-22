#!/usr/bin/env php
<?php

/**
 * dont-ship — one-file scanner for PHP & Laravel bugs that only explode in production.
 *
 *   php dont-ship.php .
 *   php dont-ship.php --json fixtures/bad
 *
 * Reads source. Never executes, includes, or evals the project it scans.
 * PHP >= 8.1. Zero dependencies.
 */

declare(strict_types=1);

final class DontShip
{
    public const VERSION = '1.0.0';

    /** @var array<string, array{severity: string, title: string, message: string, hint: string}> */
    private const META = [
        'env-outside-config' => [
            'severity' => 'critical',
            'title' => 'env() outside config/',
            'message' => 'A config helper call sits outside config/. After config is cached it returns null, and only in production.',
            'hint' => 'Move the read into a config file. Everywhere else, call config().',
        ],
        'dotenv-not-ignored' => [
            'severity' => 'critical',
            'title' => '.env is not gitignored',
            'message' => 'A .env file is present and .gitignore does not cover it. One broad add-and-commit leaks every secret in it.',
            'hint' => 'Add a line containing .env to .gitignore. Commit .env.example instead, with empty values.',
        ],
        'debug-on-in-production' => [
            'severity' => 'critical',
            'title' => 'APP_DEBUG enabled in production',
            'message' => 'APP_ENV is production while APP_DEBUG is truthy. Error pages will dump environment, queries, and secrets.',
            'hint' => 'Set APP_DEBUG=false whenever APP_ENV=production.',
        ],
        'hardcoded-secret' => [
            'severity' => 'critical',
            'title' => 'Hardcoded secret',
            'message' => 'A credential-shaped literal is sitting in source control.',
            'hint' => 'Read it from the environment via config(), and rotate the leaked value.',
        ],
        'eval-call' => [
            'severity' => 'critical',
            'title' => 'Dynamic code execution',
            'message' => 'eval() runs whatever string lands in that variable.',
            'hint' => 'Delete it. There is almost never a safe reason to keep this in an app.',
        ],
        'extract-superglobal' => [
            'severity' => 'critical',
            'title' => 'extract() on request input',
            'message' => 'extract() on a superglobal overwrites local variables with attacker-controlled names.',
            'hint' => 'Read the keys you expect explicitly. Never import a whole request into symbol scope.',
        ],
        'unserialize-input' => [
            'severity' => 'critical',
            'title' => 'unserialize() on request input',
            'message' => 'Unserializing request data is PHP object injection.',
            'hint' => 'Use json_decode. If you must unserialize, pass allowed_classes false and never feed it raw input.',
        ],
        'debug-helper' => [
            'severity' => 'high',
            'title' => 'Debug helper left in the app',
            'message' => 'A dump-and-die helper will halt the request or leak internals the moment that path is hit.',
            'hint' => 'Remove it before deploying. Log with your logger if you still need the value.',
        ],
        'raw-sql-interpolation' => [
            'severity' => 'high',
            'title' => 'Interpolated raw SQL',
            'message' => 'A raw SQL helper has a variable inside the query string.',
            'hint' => 'Use a bound placeholder (?) and pass the value in the bindings array.',
        ],
        'unguarded-model' => [
            'severity' => 'high',
            'title' => 'Model accepts every column',
            'message' => 'An empty guarded list or unguard() lets a request overwrite any column, including roles and flags.',
            'hint' => 'Declare $fillable with the fields a user may set, or keep a real $guarded list.',
        ],
        'shell-injection' => [
            'severity' => 'high',
            'title' => 'Shell command built from a variable',
            'message' => 'A shell function receives a variable as its command. That is command injection if any part is user input.',
            'hint' => 'Avoid the shell. If you cannot, escape arguments with escapeshellarg and never concatenate the command.',
        ],
        'weak-password-hash' => [
            'severity' => 'high',
            'title' => 'Password hashed with MD5 or SHA1',
            'message' => 'MD5 and SHA1 are not password hashes. They are fast to crack and have no salt story.',
            'hint' => 'Use password_hash() / password_verify(), or the framework hasher.',
        ],
        'insecure-tls' => [
            'severity' => 'high',
            'title' => 'TLS verification disabled',
            'message' => 'Certificate checks are turned off, so a network attacker can impersonate the upstream.',
            'hint' => 'Turn verification back on. Fix the certificate instead of silencing the check.',
        ],
        'csrf-wildcard' => [
            'severity' => 'high',
            'title' => 'CSRF protection disabled for every URI',
            'message' => 'The CSRF except list contains a wildcard, which turns the middleware off for the whole app.',
            'hint' => 'List concrete webhook paths only.',
        ],
        'phpinfo' => [
            'severity' => 'medium',
            'title' => 'phpinfo() reachable in source',
            'message' => 'phpinfo() prints versions, paths, and sometimes environment values.',
            'hint' => 'Remove the call. Check the runtime with the CLI, not a public route.',
        ],
        'display-errors' => [
            'severity' => 'medium',
            'title' => 'display_errors forced on',
            'message' => 'Errors are forced onto the response, including paths and configuration.',
            'hint' => 'Log errors. Do not display them outside local development.',
        ],
        'cors-wildcard' => [
            'severity' => 'medium',
            'title' => 'CORS allows every origin',
            'message' => 'Access-Control-Allow-Origin is a wildcard. Combined with credentials this is a cross-origin data leak.',
            'hint' => 'Reflect an explicit allow-list of origins.',
        ],
        'weak-token' => [
            'severity' => 'medium',
            'title' => 'Token built from a weak PRNG',
            'message' => 'rand(), mt_rand(), or uniqid() is used next to a token or secret. Those are predictable.',
            'hint' => 'Use random_bytes() or random_int() for anything that grants access.',
        ],
        'open-redirect' => [
            'severity' => 'medium',
            'title' => 'Redirect target comes from the request',
            'message' => 'A Location header or redirect is built from request input.',
            'hint' => 'Allow only relative paths you generate, or match the target against a host allow-list.',
        ],
        'without-middleware' => [
            'severity' => 'medium',
            'title' => 'Route middleware removed',
            'message' => 'withoutMiddleware() strips protection (often auth or CSRF) from a route.',
            'hint' => 'Confirm the route is public on purpose. Do not use this to "temporarily" debug.',
        ],
        'create-function' => [
            'severity' => 'low',
            'title' => 'create_function() is still here',
            'message' => 'create_function() is removed in modern PHP and evaluates a string, like eval.',
            'hint' => 'Replace it with an anonymous function.',
        ],
        'ancient-mysql' => [
            'severity' => 'low',
            'title' => 'Ancient mysql_* API',
            'message' => 'The ext/mysql functions were removed years ago and never support prepared statements.',
            'hint' => 'Use PDO or mysqli with bound parameters.',
        ],
    ];

    /**
     * @param array{ignore_rules?: list<string>, only_rules?: list<string>, ignore_paths?: list<string>} $options
     * @return array{
     *   path: string,
     *   files: int,
     *   score: int,
     *   grade: string,
     *   verdict: string,
     *   summary: array<string, int>,
     *   findings: list<array{rule: string, severity: string, title: string, file: string, line: int, message: string, hint: string, excerpt: string}>
     * }
     */
    public static function scan(string $path, array $options = []): array
    {
        $root = realpath($path);
        if ($root === false) {
            throw new InvalidArgumentException('Path not found: ' . $path);
        }

        $ignoreRules = array_flip($options['ignore_rules'] ?? []);
        $onlyRules = $options['only_rules'] ?? [];
        $onlyFlip = $onlyRules === [] ? [] : array_flip($onlyRules);
        $ignorePaths = $options['ignore_paths'] ?? [];

        $findings = [];
        $files = 0;

        if (is_file($root)) {
            $files = 1;
            $findings = self::analyzeFile($root, basename($root));
            $projectRoot = dirname($root);
        } else {
            $projectRoot = $root;
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
            );
            foreach ($iterator as $fileInfo) {
                /** @var SplFileInfo $fileInfo */
                if (!$fileInfo->isFile()) {
                    continue;
                }
                $abs = $fileInfo->getPathname();
                $rel = ltrim(str_replace('\\', '/', substr($abs, strlen($root))), '/');
                if (self::skipped($rel, $ignorePaths)) {
                    continue;
                }
                if ($fileInfo->getSize() > 700000) {
                    continue;
                }
                $batch = self::analyzeFile($abs, $rel);
                if (self::isScannable($rel)) {
                    $files++;
                }
                foreach ($batch as $finding) {
                    $findings[] = $finding;
                }
            }
        }

        if (is_file($projectRoot . DIRECTORY_SEPARATOR . '.env') && !self::envIsGitignored($projectRoot)) {
            $findings[] = self::finding('dotenv-not-ignored', '.env', 1, 'not covered by .gitignore');
        }

        $dedup = [];
        $filtered = [];
        foreach ($findings as $finding) {
            $rule = $finding['rule'];
            if (isset($ignoreRules[$rule])) {
                continue;
            }
            if ($onlyFlip !== [] && !isset($onlyFlip[$rule])) {
                continue;
            }
            $key = $rule . '|' . $finding['file'] . '|' . $finding['line'];
            if (isset($dedup[$key])) {
                continue;
            }
            $dedup[$key] = true;
            $filtered[] = $finding;
        }

        usort($filtered, static function (array $a, array $b): int {
            $order = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
            return [$order[$a['severity']], $a['file'], $a['line'], $a['rule']]
                <=> [$order[$b['severity']], $b['file'], $b['line'], $b['rule']];
        });

        $summary = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($filtered as $finding) {
            $summary[$finding['severity']]++;
        }
        $score = self::scoreFromSummary($summary);
        $grade = self::grade($score);

        return [
            'path' => $root,
            'files' => $files,
            'score' => $score,
            'grade' => $grade,
            'verdict' => self::verdict($grade),
            'summary' => $summary,
            'findings' => $filtered,
        ];
    }

    /**
     * @param array{min_score?: int|null, strict?: bool} $options
     * @param array{score: int, findings: list<array{severity: string}>} $result
     */
    public static function failed(array $result, array $options = []): bool
    {
        if (isset($options['min_score']) && $options['min_score'] !== null && $result['score'] < $options['min_score']) {
            return true;
        }
        foreach ($result['findings'] as $finding) {
            if ($finding['severity'] === 'critical' || $finding['severity'] === 'high') {
                return true;
            }
            if (($options['strict'] ?? false) && $finding['severity'] === 'medium') {
                return true;
            }
        }
        return false;
    }

    /** @param array<string, int> $summary */
    public static function scoreFromSummary(array $summary): int
    {
        $weights = ['critical' => 30, 'high' => 12, 'medium' => 4, 'low' => 1];
        $caps = ['critical' => 3, 'high' => 4, 'medium' => 5, 'low' => 5];
        $penalty = 0;
        foreach ($weights as $severity => $weight) {
            $penalty += min($summary[$severity] ?? 0, $caps[$severity]) * $weight;
        }
        return max(0, 100 - $penalty);
    }

    public static function grade(int $score): string
    {
        return match (true) {
            $score >= 100 => 'S',
            $score >= 90 => 'A',
            $score >= 75 => 'B',
            $score >= 55 => 'C',
            $score >= 30 => 'D',
            default => 'F',
        };
    }

    public static function verdict(string $grade): string
    {
        return match ($grade) {
            'S' => 'Ship it.',
            'A' => 'Clean enough. Read the notes.',
            'B' => 'Fix the highlighted ones before you deploy.',
            'C' => 'This can page you at 2am.',
            'D' => 'Do not deploy this.',
            default => 'Production would like a word.',
        };
    }

    /** @return list<array{id: string, severity: string, title: string, message: string, hint: string}> */
    public static function rules(): array
    {
        $out = [];
        foreach (self::META as $id => $meta) {
            $out[] = [
                'id' => $id,
                'severity' => $meta['severity'],
                'title' => $meta['title'],
                'message' => $meta['message'],
                'hint' => $meta['hint'],
            ];
        }
        return $out;
    }

    /**
     * @param array<string, mixed> $result
     */
    public static function render(array $result, bool $color, bool $quiet): string
    {
        $grade = (string) $result['grade'];
        $line = sprintf(
            'score %d/100   grade %s   %s',
            $result['score'],
            $grade,
            $result['verdict']
        );
        if ($quiet) {
            return self::paint($line, $grade === 'S' || $grade === 'A' ? '32' : '31', $color) . PHP_EOL;
        }

        $out = self::paint('dont-ship ' . self::VERSION, '1', $color)
            . self::paint('  ·  ne ship pas ça', '2', $color) . PHP_EOL . PHP_EOL;
        $out .= sprintf(
            "scanned %d file%s · %d finding%s" . PHP_EOL . PHP_EOL,
            $result['files'],
            ((int) $result['files'] === 1 ? '' : 's'),
            count($result['findings']),
            (count($result['findings']) === 1 ? '' : 's')
        );

        if ($result['findings'] === []) {
            $out .= self::paint('No production footguns found.' . PHP_EOL, '32', $color) . PHP_EOL;
        } else {
            foreach ($result['findings'] as $finding) {
                $sev = strtoupper((string) $finding['severity']);
                $swatch = match ($finding['severity']) {
                    'critical' => '31',
                    'high' => '91',
                    'medium' => '33',
                    default => '36',
                };
                $out .= self::paint(str_pad($sev, 8), $swatch, $color) . '  '
                    . self::paint((string) $finding['rule'], '1', $color) . PHP_EOL;
                $out .= '  ' . $finding['file'] . ':' . $finding['line'] . PHP_EOL;
                $out .= '  ' . $finding['message'] . PHP_EOL;
                if ($finding['excerpt'] !== '') {
                    $out .= self::paint('  │ ' . $finding['excerpt'], '2', $color) . PHP_EOL;
                }
                $out .= '  → ' . $finding['hint'] . PHP_EOL . PHP_EOL;
            }
        }

        $bar = str_repeat('─', 56);
        $out .= self::paint($bar . PHP_EOL . '  ' . $line . PHP_EOL . $bar . PHP_EOL, $grade === 'S' ? '32' : ($grade === 'F' || $grade === 'D' ? '31' : '33'), $color);
        return $out;
    }

    /** @param list<string> $argv */
    public static function main(array $argv): int
    {
        $color = function_exists('stream_isatty') && stream_isatty(STDOUT);
        $json = false;
        $quiet = false;
        $strict = false;
        $minScore = null;
        $ignoreRules = [];
        $onlyRules = [];
        $ignorePaths = [];
        $path = null;

        foreach (array_slice($argv, 1) as $arg) {
            if ($arg === '-h' || $arg === '--help') {
                fwrite(STDOUT, self::help());
                return 0;
            }
            if ($arg === '--version') {
                fwrite(STDOUT, self::VERSION . PHP_EOL);
                return 0;
            }
            if ($arg === '--rules') {
                foreach (self::rules() as $rule) {
                    fwrite(STDOUT, sprintf("%-8s %-24s %s\n", $rule['severity'], $rule['id'], $rule['title']));
                }
                return 0;
            }
            if ($arg === '--json') {
                $json = true;
                continue;
            }
            if ($arg === '--quiet') {
                $quiet = true;
                continue;
            }
            if ($arg === '--strict') {
                $strict = true;
                continue;
            }
            if ($arg === '--no-color') {
                $color = false;
                continue;
            }
            if ($arg === '--color') {
                $color = true;
                continue;
            }
            if (str_starts_with($arg, '--min-score=')) {
                $minScore = (int) substr($arg, strlen('--min-score='));
                continue;
            }
            if (str_starts_with($arg, '--ignore=')) {
                $ignoreRules = array_merge($ignoreRules, self::splitCsv(substr($arg, strlen('--ignore='))));
                continue;
            }
            if (str_starts_with($arg, '--only=')) {
                $onlyRules = array_merge($onlyRules, self::splitCsv(substr($arg, strlen('--only='))));
                continue;
            }
            if (str_starts_with($arg, '--ignore-path=')) {
                $ignorePaths[] = substr($arg, strlen('--ignore-path='));
                continue;
            }
            if (str_starts_with($arg, '-')) {
                fwrite(STDERR, "Unknown option: {$arg}\n\n" . self::help());
                return 2;
            }
            if ($path !== null) {
                fwrite(STDERR, "Only one path is accepted.\n\n" . self::help());
                return 2;
            }
            $path = $arg;
        }

        $path ??= getcwd() ?: '.';
        if (!file_exists($path)) {
            fwrite(STDERR, "Path not found: {$path}\n");
            return 2;
        }

        try {
            $result = self::scan($path, [
                'ignore_rules' => $ignoreRules,
                'only_rules' => $onlyRules,
                'ignore_paths' => $ignorePaths,
            ]);
        } catch (InvalidArgumentException $e) {
            fwrite(STDERR, $e->getMessage() . PHP_EOL);
            return 2;
        }

        if ($json) {
            fwrite(STDOUT, json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL);
        } else {
            fwrite(STDOUT, self::render($result, $color, $quiet));
        }

        $fail = self::failed($result, ['min_score' => $minScore, 'strict' => $strict]);
        return $fail ? 1 : 0;
    }

    private static function help(): string
    {
        return <<<TXT
dont-ship — PHP & Laravel bugs that only explode in production.

Usage:
  php dont-ship.php [options] [path]

Options:
  --json              Machine-readable report on stdout
  --min-score=N       Also fail when the score is below N
  --strict            Also fail on medium findings
  --only=a,b          Run only these rule ids
  --ignore=a,b        Skip these rule ids
  --ignore-path=frag  Skip paths containing this fragment (repeatable)
  --no-color          Plain text
  --quiet             Score line only
  --rules             List rules and exit
  --version           Print version
  -h, --help          This help

Exit codes:
  0  no critical or high finding
  1  critical or high finding, a score under --min-score, or --strict medium
  2  bad usage, or the path does not exist

The scanner only reads files. It does not include or execute the project.
PHP >= 8.1, no Composer install required.

TXT;
    }

    /** @return list<string> */
    private static function splitCsv(string $value): array
    {
        $parts = array_map('trim', explode(',', $value));
        return array_values(array_filter($parts, static fn (string $part): bool => $part !== ''));
    }

    /** @param list<string> $ignorePaths */
    private static function skipped(string $rel, array $ignorePaths): bool
    {
        $rel = str_replace('\\', '/', $rel);
        foreach ($ignorePaths as $fragment) {
            if ($fragment !== '' && str_contains($rel, $fragment)) {
                return true;
            }
        }
        $parts = explode('/', $rel);
        $blocked = ['vendor', 'node_modules', '.git', '.idea', '.vscode', 'coverage', 'dist'];
        foreach ($parts as $part) {
            if (in_array($part, $blocked, true)) {
                return true;
            }
        }
        $prefixes = ['storage/framework', 'storage/logs', 'bootstrap/cache', 'public/build', 'public/storage'];
        foreach ($prefixes as $prefix) {
            if ($rel === $prefix || str_starts_with($rel, $prefix . '/')) {
                return true;
            }
        }
        return false;
    }

    private static function isScannable(string $rel): bool
    {
        $base = basename($rel);
        return str_ends_with($base, '.php')
            || $base === '.env'
            || $base === '.env.production'
            || $base === '.env.prod'
            || $base === 'php.ini'
            || $base === '.user.ini'
            || $base === 'user.ini';
    }

    /** @return list<array{rule: string, severity: string, title: string, file: string, line: int, message: string, hint: string, excerpt: string}> */
    private static function analyzeFile(string $abs, string $rel): array
    {
        $base = basename($rel);
        $raw = @file_get_contents($abs);
        if ($raw === false || str_contains($raw, "\0")) {
            return [];
        }

        $findings = [];
        if ($base === '.env' || $base === '.env.production' || $base === '.env.prod') {
            $findings = array_merge($findings, self::analyzeEnvFile($raw, $rel));
        }
        if ($base === 'php.ini' || $base === '.user.ini' || $base === 'user.ini') {
            $findings = array_merge($findings, self::analyzeIni($raw, $rel));
        }
        if (str_ends_with($base, '.php')) {
            $findings = array_merge($findings, self::analyzePhp($raw, $rel));
        }
        return $findings;
    }

    /** @return list<array{rule: string, severity: string, title: string, file: string, line: int, message: string, hint: string, excerpt: string}> */
    private static function analyzeEnvFile(string $raw, string $rel): array
    {
        $vars = [];
        $lines = preg_split("/\r\n|\n|\r/", $raw) ?: [];
        foreach ($lines as $index => $line) {
            $trim = trim($line);
            if ($trim === '' || str_starts_with($trim, '#')) {
                continue;
            }
            if (!str_contains($trim, '=')) {
                continue;
            }
            [$key, $value] = explode('=', $trim, 2);
            $value = trim($value);
            if ($value !== '' && ($value[0] === '"' || $value[0] === "'")) {
                $quote = $value[0];
                if (str_ends_with($value, $quote) && strlen($value) >= 2) {
                    $value = substr($value, 1, -1);
                }
            }
            $vars[trim($key)] = ['value' => $value, 'line' => $index + 1];
        }

        $env = strtolower($vars['APP_ENV']['value'] ?? '');
        $debug = strtolower($vars['APP_DEBUG']['value'] ?? '');
        $truthy = ['1', 'true', 'on', 'yes'];
        if (($env === 'production' || $env === 'prod') && in_array($debug, $truthy, true)) {
            return [self::finding('debug-on-in-production', $rel, (int) $vars['APP_DEBUG']['line'], 'APP_DEBUG=' . $debug)];
        }
        return [];
    }

    /** @return list<array{rule: string, severity: string, title: string, file: string, line: int, message: string, hint: string, excerpt: string}> */
    private static function analyzeIni(string $raw, string $rel): array
    {
        $findings = [];
        $lines = preg_split("/\r\n|\n|\r/", $raw) ?: [];
        foreach ($lines as $index => $line) {
            $trim = trim($line);
            if ($trim === '' || str_starts_with($trim, ';') || str_starts_with($trim, '#')) {
                continue;
            }
            if (preg_match('/^display_errors\s*=\s*(1|on|true|yes)\b/i', $trim)) {
                $findings[] = self::finding('display-errors', $rel, $index + 1, $trim);
            }
        }
        return $findings;
    }

    /** @return list<array{rule: string, severity: string, title: string, file: string, line: int, message: string, hint: string, excerpt: string}> */
    private static function analyzePhp(string $raw, string $rel): array
    {
        if (str_ends_with($rel, '.blade.php')) {
            $raw = preg_replace('/\{\{--.*?--\}\}/s', '', $raw) ?? $raw;
        }

        [$codeOnly, $visible] = self::splitPhp($raw);
        $codeLines = preg_split("/\r\n|\n|\r/", $codeOnly) ?: [];
        $visibleLines = preg_split("/\r\n|\n|\r/", $visible) ?: [];
        $findings = [];
        $inConfig = self::isConfigFile($rel);
        $inTests = self::isTestFile($rel);

        $lineCount = max(count($codeLines), count($visibleLines));
        for ($i = 0; $i < $lineCount; $i++) {
            $codeLine = $codeLines[$i] ?? '';
            $visibleLine = $visibleLines[$i] ?? '';
            if (strlen($codeLine) > 2000) {
                $codeLine = substr($codeLine, 0, 2000);
            }
            if (strlen($visibleLine) > 2000) {
                $visibleLine = substr($visibleLine, 0, 2000);
            }
            $lineNo = $i + 1;
            $excerpt = self::excerpt($visibleLine);

            if (!$inConfig && !$inTests && preg_match('/\b(?:env|Env::get)\s*\(/', $codeLine) === 1
                && preg_match('/\bfunction\s+env\s*\(/', $codeLine) !== 1) {
                $findings[] = self::finding('env-outside-config', $rel, $lineNo, $excerpt);
            }

            if (!$inTests && preg_match('/\b(?:dd|ddd|dump|ray)\s*\(/', $codeLine) === 1
                && preg_match('/\bfunction\s+(?:dd|ddd|dump|ray)\s*\(/', $codeLine) !== 1) {
                $findings[] = self::finding('debug-helper', $rel, $lineNo, $excerpt);
            }

            if (preg_match('/\beval\s*\(/', $codeLine) === 1) {
                $findings[] = self::finding('eval-call', $rel, $lineNo, $excerpt);
            }

            if (preg_match('/\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/', $codeLine) === 1) {
                $findings[] = self::finding('extract-superglobal', $rel, $lineNo, $excerpt);
            }

            if (preg_match('/\bunserialize\s*\(/', $codeLine) === 1
                && preg_match('/allowed_classes\s*=>\s*false/', $visibleLine) !== 1) {
                $risky = preg_match('/\$_(?:GET|POST|REQUEST|COOKIE)\b|php:\/\/input|getContent\s*\(/', $codeLine) === 1;
                if ($risky) {
                    $findings[] = self::finding('unserialize-input', $rel, $lineNo, $excerpt);
                }
            }

            if (preg_match('/\b(?:whereRaw|selectRaw|orderByRaw|groupByRaw|havingRaw|joinRaw|DB::raw)\s*\(/', $codeLine) === 1
                && self::rawSqlIsInterpolated($visibleLine)) {
                $findings[] = self::finding('raw-sql-interpolation', $rel, $lineNo, $excerpt);
            }

            if (preg_match('/\b(?:shell_exec|system|exec|passthru|popen|proc_open)\s*\(\s*([^;]*)/', $codeLine, $shell) === 1) {
                $first = preg_split('/,/', $shell[1])[0] ?? '';
                if (str_contains($first, '$')) {
                    $findings[] = self::finding('shell-injection', $rel, $lineNo, $excerpt);
                }
            }

            if (preg_match('/\b(?:md5|sha1)\s*\(/i', $codeLine) === 1
                && preg_match('/password|passwd|pwd/i', $visibleLine) === 1) {
                $findings[] = self::finding('weak-password-hash', $rel, $lineNo, $excerpt);
            }

            if (preg_match('/\bphpinfo\s*\(/', $codeLine) === 1) {
                $findings[] = self::finding('phpinfo', $rel, $lineNo, $excerpt);
            }

            if (preg_match('/\bini_set\s*\(/', $codeLine) === 1
                && preg_match('/display_errors/i', $visibleLine) === 1
                && preg_match('/\b(?:1|true|on|yes)\b/i', $visibleLine) === 1) {
                $findings[] = self::finding('display-errors', $rel, $lineNo, $excerpt);
            }

            if (preg_match('/Access-Control-Allow-Origin\s*:\s*\*/i', $visibleLine) === 1) {
                $findings[] = self::finding('cors-wildcard', $rel, $lineNo, $excerpt);
            }

            if (preg_match('/\bwithoutVerifying\s*\(/', $codeLine) === 1
                || preg_match('/[\'"]verify[\'"]\s*=>\s*false\b/', $visibleLine) === 1
                || preg_match('/CURLOPT_SSL_VERIFYPEER\s*,\s*false\b/', $codeLine) === 1) {
                $findings[] = self::finding('insecure-tls', $rel, $lineNo, $excerpt);
            }

            if (preg_match('/\b(?:mt_rand|rand|uniqid)\s*\(/', $codeLine) === 1
                && preg_match('/token|password|secret|\botp\b|csrf|api[_-]?key/i', $visibleLine) === 1) {
                $findings[] = self::finding('weak-token', $rel, $lineNo, $excerpt);
            }

            if ((preg_match('/\bheader\s*\(/', $codeLine) === 1
                    && preg_match('/Location\s*:/i', $visibleLine) === 1
                    && str_contains($visibleLine, '$'))
                || preg_match('/\bredirect\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/', $codeLine) === 1) {
                $findings[] = self::finding('open-redirect', $rel, $lineNo, $excerpt);
            }

            if (preg_match('/\bwithoutMiddleware\s*\(/', $codeLine) === 1) {
                $findings[] = self::finding('without-middleware', $rel, $lineNo, $excerpt);
            }

            if (preg_match('/\bcreate_function\s*\(/', $codeLine) === 1) {
                $findings[] = self::finding('create-function', $rel, $lineNo, $excerpt);
            }

            if (preg_match('/\bmysql_(?:query|connect|real_escape_string|select_db)\s*\(/', $codeLine) === 1) {
                $findings[] = self::finding('ancient-mysql', $rel, $lineNo, $excerpt);
            }

            if (preg_match('/\bModel::unguard\s*\(/', $codeLine) === 1) {
                $findings[] = self::finding('unguarded-model', $rel, $lineNo, $excerpt);
            }

            $secret = self::secretExcerpt($visibleLine);
            if ($secret !== null) {
                $findings[] = self::finding('hardcoded-secret', $rel, $lineNo, $secret);
            }
        }

        if (preg_match('/\$guarded\s*=\s*\[\s*\]/', $codeOnly, $guarded, PREG_OFFSET_CAPTURE) === 1) {
            $lineNo = substr_count(substr($codeOnly, 0, $guarded[0][1]), "\n") + 1;
            $findings[] = self::finding('unguarded-model', $rel, $lineNo, '$guarded = []');
        }

        if (basename($rel) === 'VerifyCsrfToken.php'
            && preg_match('/\$except\s*=\s*\[(.*?)\]/s', $visible, $except) === 1
            && preg_match('/[\'"]\*[\'"]/', $except[1]) === 1) {
            $lineNo = substr_count(substr($visible, 0, (int) strpos($visible, $except[0])), "\n") + 1;
            $findings[] = self::finding('csrf-wildcard', $rel, $lineNo, '$except contains a wildcard');
        }

        return $findings;
    }

    /** A variable inside a double-quoted SQL fragment, or concatenated onto the query. */
    private static function rawSqlIsInterpolated(string $line): bool
    {
        if (preg_match('/\.\s*\$[A-Za-z_]/', $line) === 1) {
            return true;
        }
        if (preg_match_all('/"((?:\\\\.|(?!").)*)"/', $line, $matches) > 0) {
            foreach ($matches[1] as $inside) {
                if (preg_match('/\$(?:\{)?[A-Za-z_]/', $inside) === 1) {
                    return true;
                }
            }
        }
        return false;
    }

    /** @return array{0: string, 1: string} code-only (strings blanked), visible (comments blanked) */
    private static function splitPhp(string $code): array
    {
        $tokens = token_get_all($code);
        $codeOnly = '';
        $visible = '';
        foreach ($tokens as $token) {
            if (is_array($token)) {
                [$id, $text] = $token;
                $blank = preg_replace('/[^\n]/', ' ', $text) ?? $text;
                if ($id === T_COMMENT || $id === T_DOC_COMMENT) {
                    $codeOnly .= $blank;
                    $visible .= $blank;
                } elseif ($id === T_CONSTANT_ENCAPSED_STRING || $id === T_ENCAPSED_AND_WHITESPACE || $id === T_START_HEREDOC || $id === T_END_HEREDOC) {
                    $codeOnly .= $blank;
                    $visible .= $text;
                } else {
                    $codeOnly .= $text;
                    $visible .= $text;
                }
            } else {
                $codeOnly .= $token;
                $visible .= $token;
            }
        }
        return [$codeOnly, $visible];
    }

    private static function isConfigFile(string $rel): bool
    {
        $parts = explode('/', str_replace('\\', '/', $rel));
        array_pop($parts);
        return in_array('config', $parts, true);
    }

    private static function isTestFile(string $rel): bool
    {
        foreach (explode('/', str_replace('\\', '/', $rel)) as $part) {
            if ($part === 'tests' || $part === 'test' || $part === 'Tests') {
                return true;
            }
        }
        return str_ends_with($rel, 'Test.php');
    }

    private static function envIsGitignored(string $root): bool
    {
        $path = $root . DIRECTORY_SEPARATOR . '.gitignore';
        if (!is_file($path)) {
            return false;
        }
        $lines = file($path, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            return false;
        }
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#') || str_starts_with($line, '!')) {
                continue;
            }
            $line = str_replace('\\', '/', $line);
            if (in_array($line, ['.env', '/.env', '**/.env', '*.env', '.env*', '**/.env*'], true)) {
                return true;
            }
        }
        return false;
    }

    private static function secretExcerpt(string $line): ?string
    {
        if (preg_match('/AKIA[0-9A-Z]{16}/', $line) === 1) {
            return self::excerpt(preg_replace('/AKIA[0-9A-Z]{16}/', 'AKIA****************', $line) ?? $line);
        }
        if (preg_match('/sk_live_[0-9A-Za-z]{8,}/', $line) === 1) {
            return self::excerpt(preg_replace('/sk_live_[0-9A-Za-z]{8,}/', 'sk_live_********', $line) ?? $line);
        }
        if (preg_match('/ghp_[0-9A-Za-z]{20,}/', $line) === 1) {
            return self::excerpt(preg_replace('/ghp_[0-9A-Za-z]{20,}/', 'ghp_********', $line) ?? $line);
        }
        if (preg_match('/xox[baprs]-[0-9A-Za-z-]{10,}/', $line) === 1) {
            return self::excerpt(preg_replace('/xox[baprs]-[0-9A-Za-z-]{10,}/', 'xox*-********', $line) ?? $line);
        }
        $header = '-----BEGIN ' . 'PRIVATE KEY-----';
        $rsa = '-----BEGIN RSA ' . 'PRIVATE KEY-----';
        $openssh = '-----BEGIN OPENSSH ' . 'PRIVATE KEY-----';
        if (str_contains($line, $header) || str_contains($line, $rsa) || str_contains($line, $openssh)) {
            return '-----BEGIN ' . 'PRIVATE KEY----- (redacted)';
        }

        $value = null;
        if (preg_match('/\$(?:db_?)?password\s*=\s*([\'"])([^\'"]{8,})\1/i', $line, $match) === 1) {
            $value = $match[2];
        } elseif (preg_match('/([\'"])(?:password|passwd|secret|api_key|apikey)\1\s*=>\s*([\'"])([^\'"]{8,})\2/i', $line, $match) === 1) {
            $value = $match[3];
        }
        if ($value !== null && !self::placeholder($value)) {
            return self::excerpt(str_replace($value, '********', $line));
        }
        return null;
    }

    private static function placeholder(string $value): bool
    {
        $value = strtolower(trim($value));
        if (preg_match('/^(x+|\*+|change[-_ ]?me|password|secret|token|example|placeholder|todo|test|null|false|true|your[-_].*|changeme)$/', $value) === 1) {
            return true;
        }
        return str_contains($value, 'example') || str_contains($value, 'placeholder') || str_contains($value, 'your-') || str_contains($value, 'changeme');
    }

    private static function excerpt(string $line): string
    {
        $line = trim($line);
        if (strlen($line) > 160) {
            $line = substr($line, 0, 157) . '...';
        }
        return $line;
    }

    /** @return array{rule: string, severity: string, title: string, file: string, line: int, message: string, hint: string, excerpt: string} */
    private static function finding(string $rule, string $file, int $line, string $excerpt): array
    {
        $meta = self::META[$rule];
        return [
            'rule' => $rule,
            'severity' => $meta['severity'],
            'title' => $meta['title'],
            'file' => str_replace('\\', '/', $file),
            'line' => $line,
            'message' => $meta['message'],
            'hint' => $meta['hint'],
            'excerpt' => self::excerpt($excerpt),
        ];
    }

    private static function paint(string $text, string $code, bool $color): string
    {
        if (!$color) {
            return $text;
        }
        return "\033[" . $code . 'm' . $text . "\033[0m";
    }
}

if (PHP_SAPI === 'cli' && isset($argv) && realpath($argv[0]) === __FILE__) {
    exit(DontShip::main($argv));
}
