# Package Filter

> Security gate for npm/yarn/pnpm package installations. Checks blocklist,
> typosquatting, age, and popularity before allowing installs. Implemented
> in `src/server/security/package-filter.ts`.

## How It Works

When the LLM generates a package install command (`npm install`, `yarn add`,
or `pnpm add`), the package filter parses the package names and runs five
checks in order. The first failing check blocks that package; remaining
packages continue evaluation independently.

1. **Exact blocklist** -- Is the package name in the known-malicious set?
2. **Pattern blocklist** -- Does the package name match a malicious regex?
3. **Typosquatting detection** -- Is the name suspiciously close to a
   popular package (Levenshtein distance < 2)?
4. **Age check** -- Was the package first published less than 7 days ago?
5. **Popularity check** -- Does it have fewer than 50 weekly downloads?

## Check 1: Known Malicious Packages (Exact Match)

The following 30 package names are blocked immediately. These are real
supply-chain attack packages that were published to npm.

| Package | Reason |
|---|---|
| `crossenv` | Typosquat of cross-env; stole env vars |
| `cross-env.js` | Typosquat variant |
| `crossenv.js` | Typosquat variant |
| `d3.js` | Typosquat of d3 |
| `gruntcli` | Typosquat of grunt-cli |
| `http-proxy.js` | Typosquat of http-proxy |
| `jquery.js` | Typosquat of jquery |
| `mariadb` | Malicious npm package (not the real MariaDB connector) |
| `mongose` | Typosquat of mongoose |
| `mssql.js` | Typosquat of mssql |
| `mssql-node` | Typosquat of mssql |
| `mysqljs` | Typosquat of mysql |
| `node-fabric` | Typosquat of fabric |
| `node-opencv` | Malicious package |
| `node-opensl` | Typosquat of node-openssl |
| `node-openssl` | Malicious package |
| `nodecaffe` | Malicious package |
| `nodefabric` | Typosquat variant |
| `nodeffmpeg` | Typosquat of fluent-ffmpeg |
| `nodemailer-js` | Typosquat of nodemailer |
| `noderequest` | Typosquat of request |
| `nodesass` | Typosquat of node-sass |
| `nodesqlite` | Typosquat of better-sqlite3 |
| `nodest` | Malicious package |
| `shadowsock` | Typosquat of shadowsocks |
| `smb` | Malicious package |
| `sqlite.js` | Typosquat of better-sqlite3 |
| `sqliter` | Typosquat |
| `sqlserver` | Typosquat of mssql |
| `tkinter` | Malicious package (Python name on npm) |

## Check 2: Malicious Pattern Match

These regex patterns catch entire categories of malicious packages.

| Pattern | What It Catches |
|---|---|
| `/^@evildomain\//` | Scoped packages from known-malicious orgs |
| `/^crossenv$/` | The crossenv typosquat |
| `/^event-stream$/` | The 2018 event-stream supply-chain attack |
| `/^flatmap-stream$/` | The malicious dependency from event-stream |
| `/^coa$/` | Compromised package (November 2021) |
| `/^rc$/` | Compromised package (November 2021) |
| `/^ua-parser-js$/` | Compromised package (October 2021) |
| `/^colors$/` | Sabotaged by maintainer (January 2022) |
| `/^faker$/` | Sabotaged by maintainer (January 2022) |
| `/-malware$/` | Packages with `-malware` suffix |
| `/^npm-script-/` | Malicious `npm-script-*` family |
| `/^node-hide-console-windows$/` | Malicious package |

## Check 3: Typosquatting Detection

The filter computes the Levenshtein edit distance between the requested
package name and a list of 50 popular npm packages. If the distance is
exactly 1 (one character insertion, deletion, or substitution), the install
is blocked.

**Distance threshold**: < 2 (i.e., distance must be exactly 1 to trigger)

**Protected packages** (50 total):

```
react, react-dom, next, express, lodash, axios, typescript,
webpack, babel, eslint, prettier, jest, mocha, chai,
moment, dayjs, date-fns, uuid, dotenv, cors, body-parser,
mongoose, sequelize, prisma, knex, pg, mysql2, redis,
socket.io, graphql, apollo, fastify, koa, hapi, nest,
tailwindcss, postcss, autoprefixer, sass, less, styled-components,
chalk, commander, yargs, inquirer, ora, debug, winston,
nodemon, concurrently, cross-env, rimraf, glob, fs-extra
```

**Example**: `npm install expresss` is blocked because
`levenshtein("expresss", "express") = 1`.

## Check 4: Package Age

The filter queries the npm registry (`registry.npmjs.org`) for the
package's creation date. Packages published less than **7 days** ago are
blocked.

- Registry responses are cached in a TTL cache (10 minutes, 600,000ms).
- Requests have a 5-second timeout via `AbortSignal.timeout(5000)`.
- If the package is not found on the registry, it is blocked with reason
  `not_found`.

## Check 5: Weekly Download Count

The filter queries the npm downloads API
(`api.npmjs.org/downloads/point/last-week/{pkg}`) for the package's weekly
download count. Packages with fewer than **50 downloads per week** are
blocked.

- Download counts are cached in a TTL cache (5 minutes, 300,000ms).
- Requests have a 5-second timeout.

## Caching

Two independent TTL caches prevent excessive registry requests:

| Cache | TTL | What It Stores |
|---|---|---|
| `registryCache` | 10 minutes (600,000ms) | Package metadata (creation date) |
| `downloadsCache` | 5 minutes (300,000ms) | Weekly download counts |

## Block Reasons

| Reason Code | Meaning |
|---|---|
| `known_malicious` | Package is in the exact-match blocklist |
| `malicious_pattern` | Package name matches a malicious regex pattern |
| `typosquatting` | Levenshtein distance < 2 from a popular package |
| `too_new` | Package was published less than 7 days ago |
| `low_popularity` | Fewer than 50 weekly downloads |
| `not_found` | Package does not exist on the npm registry |

## Related Docs

- [Output Filter](output-filter.md) -- The command denylist that runs
  alongside the package filter
- [Code Scanning](code-scanning.md) -- SCA scanner that checks installed
  dependencies for known vulnerabilities
- [Security Overview](README.md) -- Where this layer fits in the stack
