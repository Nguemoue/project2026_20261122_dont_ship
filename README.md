# dont-ship

**Ne ship pas ça.** Un fichier. Zéro dépendance. Les bugs PHP et Laravel qui passent en local et explosent après le déploiement.

`config:cache` · `env()` hors de `config/` · `dd()` oublié · `.env` versionné · SQL interpolé · secrets en dur

```bash
curl -fsSL https://raw.githubusercontent.com/Nguemoue/project2026_20261122_dont_ship/main/dont-ship.php -o dont-ship.php
php dont-ship.php .
```

Exit `0` s'il n'y a rien de critical/high. Exit `1` sinon. Branche-le sur la CI et arrête de découvrir `null` en production.

---

## Pourquoi

`php artisan config:cache` fige la config. Après ça, `env()` **en dehors** de `config/` renvoie `null`. Uniquement en prod. Le site marche sur ta machine.

dont-ship lit le code. Il ne l'exécute pas, ne l'inclut pas, n'évalue rien.

Un seul `env()` hors de `config/` :

```text
CRITICAL  env-outside-config
  app/Foo.php:3
  │ $x = env('FOO');
  → Move the read into a config file. Everywhere else, call config().

  score 70/100   grade C   This can page you at 2am.
```

Un projet propre :

```text
scanned 8 files · 0 findings
No production footguns found.
  score 100/100   grade S   Ship it.
```

Le dossier [`fixtures/bad`](fixtures/bad) est **volontairement** vulnérable (clé AWS de la doc officielle, pas un secret réel). Il sort **0/100, grade F, 25 findings**. [`fixtures/good`](fixtures/good) sort **100/100**.

## Usage

```bash
php dont-ship.php                      # dossier courant
php dont-ship.php --json .             # pour un bot / une CI
php dont-ship.php --min-score=90 .
php dont-ship.php --strict .           # échoue aussi sur les medium
php dont-ship.php --ignore=phpinfo,ancient-mysql .
php dont-ship.php --only=env-outside-config .
php dont-ship.php --ignore-path=fixtures .
php dont-ship.php --rules
```

| Code | Quand |
| --- | --- |
| 0 | aucun critical, aucun high |
| 1 | critical ou high, score sous `--min-score`, ou medium avec `--strict` |
| 2 | mauvais arguments, ou chemin introuvable |

Le score part de 100. Un critical vaut −30 (plafonné à 3), un high −12 (plafonné à 4), un medium −4, un low −1. Le plafond empêche un seul type de bruit d'écraser le grade. **S = 100**, rien trouvé.

| Grade | Score | |
| --- | --- | --- |
| S | 100 | Ship it. |
| A | 90–99 | Clean enough. Read the notes. |
| B | 75–89 | Fix the highlighted ones before you deploy. |
| C | 55–74 | This can page you at 2am. |
| D | 30–54 | Do not deploy this. |
| F | 0–29 | Production would like a word. |

PHP `>= 8.1`. Pas besoin de `composer install`.

```bash
git clone https://github.com/Nguemoue/project2026_20261122_dont_ship.git
cd project2026_20261122_dont_ship
php tests/self-test.php
php dont-ship.php fixtures/bad
```

## Ce qui est cherché

| Règle | Niveau | Ce qui casse en prod |
| --- | --- | --- |
| `env-outside-config` | critical | `env()` / `Env::get()` hors de `config/` → `null` après `config:cache` |
| `dotenv-not-ignored` | critical | un `.env` à la racine n'est pas couvert par `.gitignore` |
| `debug-on-in-production` | critical | `APP_ENV=production` et `APP_DEBUG=true` |
| `hardcoded-secret` | critical | clé AWS, Stripe live, GitHub, Slack, clé privée, mot de passe en dur |
| `eval-call` | critical | `eval()` |
| `extract-superglobal` | critical | `extract($_GET\|$_POST\|…)` |
| `unserialize-input` | critical | `unserialize()` sur l'entrée HTTP |
| `debug-helper` | high | `dd()`, `ddd()`, `dump()`, `ray()` |
| `raw-sql-interpolation` | high | `whereRaw` / `DB::raw` avec une variable dans la chaîne ou concaténée |
| `unguarded-model` | high | `$guarded = []` ou `Model::unguard()` |
| `shell-injection` | high | `shell_exec` / `exec` / `system` / … dont le premier argument est une variable |
| `weak-password-hash` | high | `md5` / `sha1` à côté d'un mot de passe |
| `insecure-tls` | high | `withoutVerifying()`, `verify => false`, `CURLOPT_SSL_VERIFYPEER, false` |
| `csrf-wildcard` | high | `$except` contient `'*'` dans `VerifyCsrfToken.php` |
| `phpinfo` | medium | `phpinfo()` |
| `display-errors` | medium | `display_errors` forcé à on |
| `cors-wildcard` | medium | `Access-Control-Allow-Origin: *` |
| `weak-token` | medium | `rand` / `mt_rand` / `uniqid` à côté d'un token, otp, secret |
| `open-redirect` | medium | `Location` ou `redirect($_GET…)` construit depuis la requête |
| `without-middleware` | medium | `withoutMiddleware()` |
| `create-function` | low | `create_function()` |
| `ancient-mysql` | low | `mysql_query` et la vieille API `mysql_*` |

`whereRaw('prix > ?', [$prix])` ne sonne pas. `env()` **dans** `config/` non plus. Un `mt_rand(1, 6)` pour un dé non plus. Les commentaires et les chaînes de documentation ne comptent pas comme du code.

Les secrets dans le rapport sont masqués. Le contenu de `.env` n'est pas recopié, à part le fait que `APP_DEBUG` est actif.

## CI

Copie [`examples/github-action.yml`](examples/github-action.yml) dans ton app :

```yaml
- uses: shivammathur/setup-php@v2
  with:
    php-version: "8.3"
- run: php dont-ship.php --no-color .
```

Ce dépôt, lui, lance `php tests/self-test.php` : le fixture cassé doit scorer 0, le fixture sain 100, et le scanner ne doit pas se signaler lui-même.

## Volontairement pas couvert

Pas un audit complet. Pas de résolution de `include` dynamique, pas de suivi de variables sur plusieurs lignes, pas de `getenv()` (légitime dans plein de scripts PHP hors Laravel). `unserialize()` n'est signalé que s'il touche la requête. L'outil préfère un rapport qu'on lit à un rapport qu'on ignore.

## Licence

[MIT](LICENSE) © 2026 Nguemoue
