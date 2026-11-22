<?php

declare(strict_types=1);

$root = dirname(__DIR__);
require $root . '/dont-ship.php';

$failures = 0;

function check(bool $condition, string $message): void
{
    global $failures;
    if ($condition) {
        return;
    }
    fwrite(STDERR, "FAIL: {$message}\n");
    $failures++;
}

function run_cli(string $args): array
{
    $root = dirname(__DIR__);
    $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($root . '/dont-ship.php') . ' ' . $args;
    $pipes = [];
    $process = proc_open($command, [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ], $pipes);
    if (!is_resource($process)) {
        fwrite(STDERR, "FAIL: could not start php\n");
        exit(1);
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exit = proc_close($process);

    return ['exit' => $exit, 'stdout' => (string) $stdout, 'stderr' => (string) $stderr];
}

$expected = [
    'env-outside-config',
    'dotenv-not-ignored',
    'debug-on-in-production',
    'hardcoded-secret',
    'eval-call',
    'extract-superglobal',
    'unserialize-input',
    'debug-helper',
    'raw-sql-interpolation',
    'unguarded-model',
    'shell-injection',
    'weak-password-hash',
    'insecure-tls',
    'csrf-wildcard',
    'phpinfo',
    'display-errors',
    'cors-wildcard',
    'weak-token',
    'open-redirect',
    'without-middleware',
    'create-function',
    'ancient-mysql',
];

$bad = DontShip::scan($root . '/fixtures/bad');
$badRules = array_values(array_unique(array_column($bad['findings'], 'rule')));
sort($badRules);
$expectedSorted = $expected;
sort($expectedSorted);
check($badRules === $expectedSorted, 'bad fixture rules mismatch: ' . json_encode($badRules));
check($bad['score'] === 0, 'bad score should be 0, got ' . $bad['score']);
check($bad['grade'] === 'F', 'bad grade should be F, got ' . $bad['grade']);
check(DontShip::failed($bad), 'bad fixture should fail the gate');

foreach ($bad['findings'] as $finding) {
    if ($finding['rule'] === 'env-outside-config') {
        check(!str_contains($finding['file'], 'config/'), 'env() inside config/ was flagged: ' . $finding['file']);
    }
}

$encoded = json_encode($bad);
check(is_string($encoded), 'bad report json');
check(!str_contains((string) $encoded, 'AKIAIOSFODNN7EXAMPLE'), 'live-looking key leaked into the report');
check(str_contains((string) $encoded, 'AKIA****************'), 'redacted key marker missing');
check(!str_contains((string) $encoded, 'hunter2hunter2'), 'password literal leaked into the report');
check(!str_contains((string) $encoded, 'not-printed'), '.env secret leaked into the report');

$good = DontShip::scan($root . '/fixtures/good');
check($good['findings'] === [], 'good fixture should be clean: ' . json_encode($good['findings']));
check($good['score'] === 100 && $good['grade'] === 'S', 'good score/grade');
check(!DontShip::failed($good), 'good fixture should pass the gate');

$one = DontShip::scan($root . '/fixtures/one');
check(count($one['findings']) === 1, 'one fixture should have a single finding');
check(($one['findings'][0]['rule'] ?? '') === 'env-outside-config', 'one fixture rule');
check($one['score'] === 70 && $one['grade'] === 'C', 'one env() call should score 70/C, got ' . $one['score'] . '/' . $one['grade']);

$ignored = DontShip::scan($root . '/fixtures/one', ['ignore_rules' => ['env-outside-config']]);
check($ignored['findings'] === [] && $ignored['score'] === 100, 'ignore_rules should silence the hit');

$only = DontShip::scan($root . '/fixtures/bad', ['only_rules' => ['phpinfo']]);
check(count($only['findings']) === 1 && $only['findings'][0]['rule'] === 'phpinfo', '--only equivalent should keep one rule');

$self = DontShip::scan($root . '/dont-ship.php');
check($self['findings'] === [], 'scanner source should not flag itself: ' . json_encode($self['findings']));

$cliGood = run_cli('--no-color ' . escapeshellarg($root . '/fixtures/good'));
check($cliGood['exit'] === 0, 'CLI good exit ' . $cliGood['exit'] . ' ' . $cliGood['stderr']);
check(str_contains($cliGood['stdout'], 'score 100/100'), 'CLI good score line missing');
check(str_contains($cliGood['stdout'], 'Ship it.'), 'CLI verdict missing');

$cliBad = run_cli('--no-color ' . escapeshellarg($root . '/fixtures/bad'));
check($cliBad['exit'] === 1, 'CLI bad should exit 1, got ' . $cliBad['exit']);
check(str_contains($cliBad['stdout'], 'grade F'), 'CLI bad grade missing');

$cliJson = run_cli('--json ' . escapeshellarg($root . '/fixtures/one'));
$decoded = json_decode($cliJson['stdout'], true);
check(is_array($decoded) && ($decoded['score'] ?? null) === 70, 'JSON score mismatch: ' . $cliJson['stdout']);
check($cliJson['exit'] === 1, 'JSON run should still exit 1');

$cliRules = run_cli('--rules');
check($cliRules['exit'] === 0 && str_contains($cliRules['stdout'], 'env-outside-config'), 'rules list');

$cliMissing = run_cli(escapeshellarg($root . '/does-not-exist'));
check($cliMissing['exit'] === 2, 'missing path should exit 2');

$cliUsage = run_cli('--not-a-flag');
check($cliUsage['exit'] === 2, 'unknown flag should exit 2');

$ruleIds = array_column(DontShip::rules(), 'id');
sort($ruleIds);
check($ruleIds === $expectedSorted, 'META is missing a rule from the fixture contract');

if ($failures > 0) {
    fwrite(STDERR, "{$failures} failure(s)\n");
    exit(1);
}

fwrite(STDOUT, 'OK ' . count($expected) . " rules, bad=0/F good=100/S one=70/C, scanner is clean\n");
