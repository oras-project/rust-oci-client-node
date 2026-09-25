const fs = require('fs');
const args = process.argv.slice(2);
const checkOnly = args.includes('--check');
const tagIdx = args.indexOf('--tag');
const tag = tagIdx !== -1 ? args[tagIdx + 1]?.replace(/^v/, '') : null;

const cargo = fs.readFileSync('Cargo.toml', 'utf8').match(/^version = "(.+)"/m)?.[1];

if (!cargo) {
  console.error('Could not read version from Cargo.toml');
  process.exit(1);
}

// Helper to strip -prerelease and +build metadata
const getBaseVersion = (v) => (v ? v.split(/[-+]/)[0] : '');

const pkgPath = 'package.json';
const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));

console.log(`Cargo.toml: ${cargo} | package.json: ${pkg.version}${tag ? ` | tag: ${tag}` : ''}`);

let failed = false;

if (tag && pkg.version !== tag) {
  console.error(`::error::package.json version (${pkg.version}) does not match git tag (${tag})`);
  failed = true;
}

// 2. Base version of package.json must match version of Cargo.toml
const pkgBase = getBaseVersion(pkg.version);

if (cargo !== pkgBase) {
  if (checkOnly) {
    console.error(
      `::error::package.json version (${pkgBase}) does not match Cargo.toml version (${cargo})`,
    );
    failed = true;
  } else {
    pkg.version = cargo;
    fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
    console.log('Synced package.json version to', cargo);
  }
} else {
  console.log('Versions in sync:', cargo, '=>', pkg.version);
}

// 3. Keep testing/package.json version in lockstep with main package.json
const testingPkgPath = 'testing/package.json';
if (fs.existsSync(testingPkgPath)) {
  const testingPkg = JSON.parse(fs.readFileSync(testingPkgPath, 'utf8'));
  if (testingPkg.version !== pkg.version) {
    if (checkOnly) {
      console.error(
        `::error::testing/package.json version (${testingPkg.version}) does not match package.json (${pkg.version})`,
      );
      failed = true;
    } else {
      testingPkg.version = pkg.version;
      fs.writeFileSync(testingPkgPath, JSON.stringify(testingPkg, null, 2) + '\n');
      console.log('Synced testing/package.json version to', pkg.version);
    }
  } else {
    console.log('testing/package.json version in sync:', pkg.version);
  }
}

if (failed) process.exit(1);