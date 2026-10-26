# PHP built from source

The PHP page lets ServanaGo compile PHP itself, for when a security release must not wait for your distribution's package mirrors.

## What it does

- Downloads the release from php.net (sha256 and GPG signature checked).
- Compiles it with its own copies of the libraries it needs.
- Installs it root-owned under `/opt/servanago/php` (`<version>-<n>`, libraries in `…/libs`).
- Runs the build as an unprivileged user in a sandboxed unit (half the CPU, 4 GB of memory).

The host needs only a C and C++ toolchain, pkg-config, cmake, perl, bison, flex, autoconf, automake, libtool, m4, gpg, xz and tar. A missing one is listed with its `apt install` line.

## Using a build

- Each site picks a branch (`8.4`, follows the newest build) or an exact build (`8.4.27-1`).
- Each site has its own set of extensions: 19 shared ones, including the PECL extensions apcu and imagick.
- Switching moves the sites one at a time and puts a site back on the previous build if it does not come up.
- Each login user can have a default command-line `php` and `composer`.
- A weekly check against php.net shows new releases (security ones marked) and emails the MAIL FROM address.

## What is verified and what is trusted

Verified:

- The PHP download, against the sha256 php.net publishes and a GPG signature from a PHP release manager. The keyring is embedded in the binary and was fetched once from php.net, so those keys are trusted on first use.
- Each library, against the checksum its project publishes. Exceptions: libpng, freetype, libwebp and gmp are fixed to a checksum checked when it was added (newer releases of those need a ServanaGo update), and sqlite uses SHA3-256, the only hash it publishes.

Only trusted:

- The source of **apcu** and **imagick** comes from Packagist and GitHub over HTTPS at the commit Packagist names, because neither publishes a checksum. The build log records each commit and download hash. A compromise of Packagist or GitHub could put malicious code into an extension that php-fpm loads as the site user.

Build isolation:

- The build runs as an unprivileged user with no network while compiling.
- Only the final copy runs as root; it refuses symlinks that leave the tree and clears setuid and group/world-write bits.
- The helper runs the new `php` once as root to check its version, and php-fpm runs as root, so a build is root-trusted code. Treat the checks above as the whole defence.

## Backups and restores

Builds, their libraries and their logs (`/var/log/servanago/php-build-*.log`) are not backed up by ServanaGo. After a restore on a new host, build PHP again; sites that follow a branch pick it up. A site pinned to an exact build that no longer exists falls back to the newest build of its branch, or fails with a message if there is none.

Do not restart `servanago` during a build.

## More

Design and what differs from the plan: [php-from-source-design.md](php-from-source-design.md), section 16. Requirements: [php-from-source-requirements.md](php-from-source-requirements.md).
