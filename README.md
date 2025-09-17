# SecretSnipe - Advanced Secret Detection Platform

A comprehensive secret detection and visualization platform built with PostgreSQL, Redis, and Docker for enterprise-grade security scanning.

## 🚀 Features

- **Multi-Format Support**: Scans 25+ file types including PDFs, Office documents, images, and archives
- **Multi-Tool Integration**: Supports custom regex, Trufflehog, and Gitleaks scanners
- **PostgreSQL Backend**: ACID-compliant database with full audit trails
- **Redis Caching**: High-performance caching and session management
- **Interactive Dashboard**: Real-time visualization with Dash/Plotly
- **Configurable Reports**: Automated report generation with multiple formats
- **Webhook Notifications**: Real-time alerts for severe security findings
- **Docker Ready**: Complete containerization for Linux deployment
- **Parallel Processing**: Multi-threaded scanning for large codebases

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Dashboard │    │   REST API      │    │   Webhook       │
│   (Dash/Plotly) │    │   (Flask)       │    │   Service       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
          │                       │                       │
          └───────────────────────┼───────────────────────┘
                                  │
                    ┌─────────────────┐
                    │   Redis Cache   │
                    │   (Sessions)    │
                    └─────────────────┘
                                  │
                    ┌─────────────────┐
                    │ PostgreSQL DB   │
                    │   (Findings)    │
                    └─────────────────┘
                                  │
                    ┌─────────────────┐
                    │   Scanner       │
                    │   (Custom +     │
                    │    External)    │
                    └─────────────────┘
```

## 📋 Prerequisites

- Docker and Docker Compose
- 4GB RAM minimum (8GB recommended)
- PostgreSQL 15+ (via Docker)
- Redis 7+ (via Docker)

## 🚀 Quick Start with Docker

### 1. Clone and Setup

```bash
git clone https://github.com/your-org/secretsnipe.git
cd secretsnipe
```

### 2. Environment Configuration

Create a `.env` file:

```bash
# Database
POSTGRES_PASSWORD=your_secure_password_here

# Webhook (optional)
WEBHOOK_URL=https://your-webhook-endpoint.com/notify
```

### 3. Launch the Platform

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### 4. Access the Dashboard

- **Dashboard**: http://localhost:8050
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

## 🔧 Manual Installation

### Local Development Setup

1. **Install Dependencies**
```bash
pip install -r requirements.txt
```

2. **Setup PostgreSQL**
```bash
# Install PostgreSQL locally or use Docker
docker run -d --name postgres -p 5432:5432 \
  -e POSTGRES_DB=secretsnipe \
  -e POSTGRES_USER=secretsnipe \
  -e POSTGRES_PASSWORD=your_password \
  postgres:15-alpine
```

3. **Setup Redis**
```bash
# Install Redis locally or use Docker
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

4. **Initialize Database**
```bash
# Run schema setup
psql -h localhost -U secretsnipe -d secretsnipe -f database_schema.sql
```

5. **Configure Application**
```bash
# Copy and edit configuration
cp config.json config.local.json
# Edit config.local.json with your settings
```

## 📊 Usage

### Scanning a Directory

```bash
# Using Docker
docker-compose exec scanner python secret_snipe_pg.py /path/to/scan --project my-project

# Using local installation
python secret_snipe_pg.py /path/to/scan --project my-project
```

### Multi-Tool Scanning

```bash
# Run all tools (custom + external)
python run_secret_scanner_pg.py /path/to/scan --tools custom,trufflehog,gitleaks
```

### Accessing the Dashboard

```bash
# Start the visualizer
python unified_visualizer_pg.py
# Open http://localhost:8050
```

### Continuous Monitoring

Enable continuous monitoring to automatically scan file changes:

```bash
# Using Docker (with monitoring profile)
docker-compose --profile monitoring up -d

# Set monitoring path
export MONITOR_PATH=/path/to/monitor

# Set Teams webhook for weekly reports
export TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/your-webhook-url

# Start monitoring
docker-compose --profile monitoring up continuous-monitor -d
```

**Weekly Reports**: Automatic Teams notifications every Monday at 9:00 AM with:
- 📊 Total findings breakdown
- 🚨 Critical/high severity counts
- 🔍 Scanner-specific statistics
- 📈 Trends and patterns

**Real-time Alerts**: Immediate webhook notifications for critical findings.

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_HOST` | PostgreSQL host | localhost |
| `DB_PORT` | PostgreSQL port | 5432 |
| `DB_NAME` | Database name | secretsnipe |
| `DB_USER` | Database user | secretsnipe |
| `DB_PASSWORD` | Database password | (required) |
| `REDIS_HOST` | Redis host | localhost |
| `REDIS_PORT` | Redis port | 6379 |
| `LOG_LEVEL` | Logging level | INFO |
| `DEBUG` | Debug mode | false |

### Webhook Configuration

Configure webhooks in `config.json`:

```json
{
  "webhook": {
    "enabled": true,
    "url": "https://your-endpoint.com/webhook",
    "method": "POST",
    "headers": {
      "Authorization": "Bearer your-token",
      "Content-Type": "application/json"
    }
  }
}
```

## 🔍 Supported File Types

- **Code Files**: `.py`, `.js`, `.ts`, `.java`, `.cpp`, `.c`, `.php`, `.rb`, `.go`, `.rs`
- **Config Files**: `.json`, `.xml`, `.yaml`, `.toml`, `.ini`, `.cfg`, `.env`
- **Documents**: `.pdf`, `.docx`, `.xlsx`, `.txt`, `.md`
- **Images**: `.jpg`, `.png`, `.bmp`, `.tiff` (with OCR)
- **Archives**: `.zip` (recursive extraction)

## 📈 Performance Tuning

### Database Optimization

```sql
-- Create indexes for better performance
CREATE INDEX CONCURRENTLY idx_findings_composite
ON findings(project_id, scan_session_id, severity, first_seen DESC);

-- Partition large tables by date
CREATE TABLE findings_y2025 PARTITION OF findings
FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
```

### Redis Configuration

```redis.conf
# Memory management
maxmemory 512mb
maxmemory-policy allkeys-lru

# Persistence
appendonly yes
appendfsync everysec
```

### Scanner Optimization

```json
{
  "scanner": {
    "threads": 8,
    "timeout_seconds": 600,
    "max_file_size_mb": 50
  }
}
```

## 🔐 Security Features

- **Secret Masking**: Automatic masking of detected secrets
- **Audit Logging**: Complete audit trail of all operations
- **Access Control**: Role-based access control (RBAC)
- **Encryption**: Optional encryption for sensitive data
- **Webhook Security**: HMAC signature validation

## 📊 Monitoring and Alerts

### Health Checks

```bash
# Check all services
docker-compose ps

# Database health
docker-compose exec postgres pg_isready -U secretsnipe

# Redis health
docker-compose exec redis redis-cli ping
```

### Log Analysis

```bash
# View application logs
docker-compose logs scanner
docker-compose logs visualizer

# Database logs
docker-compose logs postgres
```

## 🛠️ Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest

# Run with coverage
pytest --cov=secretsnipe --cov-report=html
```

### Code Quality

```bash
# Format code
black .

# Lint code
flake8 .

# Type checking
mypy .
```

## 📚 API Documentation

### REST Endpoints

- `GET /api/projects` - List projects
- `GET /api/findings` - Get findings with filters
- `POST /api/scan` - Start new scan
- `GET /api/reports` - Generate reports

### Webhook Payload

```json
{
  "event": "new_finding",
  "finding": {
    "id": "uuid",
    "file_path": "/path/to/file",
    "secret_type": "API Key",
    "severity": "High",
    "context": "line context...",
    "timestamp": "2025-01-15T10:30:00Z"
  },
  "project": {
    "id": "uuid",
    "name": "my-project"
  }
}
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Documentation**: See `/docs` directory
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions

## 🔄 Migration from LMDB

If migrating from the old LMDB-based version:

1. Export existing findings: `python migrate_from_lmdb.py`
2. Update configuration to use PostgreSQL
3. Run database schema setup
4. Import data: `python import_legacy_data.py`

---

**Built with ❤️ for secure software development**

## Discovery 🔍

TruffleHog can look for secrets in many places including Git, chats, wikis, logs, API testing platforms, object stores, filesystems and more

## Classification 📁

TruffleHog classifies over 800 secret types, mapping them back to the specific identity they belong to. Is it an AWS secret? Stripe secret? Cloudflare secret? Postgres password? SSL Private key? Sometimes it's hard to tell looking at it, so TruffleHog classifies everything it finds.

## Validation ✅

For every secret TruffleHog can classify, it can also log in to confirm if that secret is live or not. This step is critical to know if there’s an active present danger or not.

## Analysis 🔬

For the 20 some of the most commonly leaked out credential types, instead of sending one request to check if the secret can log in, TruffleHog can send many requests to learn everything there is to know about the secret. Who created it? What resources can it access? What permissions does it have on those resources?

# :loudspeaker: Join Our Community

Have questions? Feedback? Jump into Slack or Discord and hang out with us.

Join our [Slack Community](https://join.slack.com/t/trufflehog-community/shared_invite/zt-pw2qbi43-Aa86hkiimstfdKH9UCpPzQ)

Join the [Secret Scanning Discord](https://discord.gg/8Hzbrnkr7E)

# :tv: Demo

![GitHub scanning demo](https://storage.googleapis.com/truffle-demos/non-interactive.svg)

```bash
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity
```

# :floppy_disk: Installation

Several options are available for you:

### MacOS users

```bash
brew install trufflehog
```

### Docker:

<sub><i>_Ensure Docker engine is running before executing the following commands:_</i></sub>

#### &nbsp;&nbsp;&nbsp;&nbsp;Unix

```bash
docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys
```

#### &nbsp;&nbsp;&nbsp;&nbsp;Windows Command Prompt

```bash
docker run --rm -it -v "%cd:/=\%:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys
```

#### &nbsp;&nbsp;&nbsp;&nbsp;Windows PowerShell

```bash
docker run --rm -it -v "${PWD}:/pwd" trufflesecurity/trufflehog github --repo https://github.com/trufflesecurity/test_keys
```

#### &nbsp;&nbsp;&nbsp;&nbsp;M1 and M2 Mac

```bash
docker run --platform linux/arm64 --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys
```

### Binary releases

```bash
Download and unpack from https://github.com/trufflesecurity/trufflehog/releases
```

### Compile from source

```bash
git clone https://github.com/trufflesecurity/trufflehog.git
cd trufflehog; go install
```

### Using installation script

```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

### Using installation script, verify checksum signature (requires cosign to be installed)

```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -v -b /usr/local/bin
```

### Using installation script to install a specific version

```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin <ReleaseTag like v3.56.0>
```

# :closed_lock_with_key: Verifying the artifacts

Checksums are applied to all artifacts, and the resulting checksum file is signed using cosign.

You need the following tool to verify signature:

- [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/)

Verification steps are as follows:

1. Download the artifact files you want, and the following files from the [releases](https://github.com/trufflesecurity/trufflehog/releases) page.

   - trufflehog\_{version}\_checksums.txt
   - trufflehog\_{version}\_checksums.txt.pem
   - trufflehog\_{version}\_checksums.txt.sig

2. Verify the signature:

   ```shell
   cosign verify-blob <path to trufflehog_{version}_checksums.txt> \
   --certificate <path to trufflehog_{version}_checksums.txt.pem> \
   --signature <path to trufflehog_{version}_checksums.txt.sig> \
   --certificate-identity-regexp 'https://github\.com/trufflesecurity/trufflehog/\.github/workflows/.+' \
   --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
   ```

3. Once the signature is confirmed as valid, you can proceed to validate that the SHA256 sums align with the downloaded artifact:

   ```shell
   sha256sum --ignore-missing -c trufflehog_{version}_checksums.txt
   ```

Replace `{version}` with the downloaded files version

Alternatively, if you are using the installation script, pass `-v` option to perform signature verification.
This requires Cosign binary to be installed prior to running the installation script.

# :rocket: Quick Start

## 1: Scan a repo for only verified secrets

Command:

```bash
trufflehog git https://github.com/trufflesecurity/test_keys --results=verified,unknown
```

Expected output:

```
🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷

Found verified result 🐷🔑
Detector Type: AWS
Decoder Type: PLAIN
Raw result: AKIAYVP4CIPPERUVIFXG
Line: 4
Commit: fbc14303ffbf8fb1c2c1914e8dda7d0121633aca
File: keys
Email: counter <counter@counters-MacBook-Air.local>
Repository: https://github.com/trufflesecurity/test_keys
Timestamp: 2022-06-16 10:17:40 -0700 PDT
...
```

## 2: Scan a GitHub Org for only verified secrets

```bash
trufflehog github --org=trufflesecurity --results=verified,unknown
```

## 3: Scan a GitHub Repo for only verified keys and get JSON output

Command:

```bash
trufflehog git https://github.com/trufflesecurity/test_keys --results=verified,unknown --json
```

Expected output:

```
{"SourceMetadata":{"Data":{"Git":{"commit":"fbc14303ffbf8fb1c2c1914e8dda7d0121633aca","file":"keys","email":"counter \u003ccounter@counters-MacBook-Air.local\u003e","repository":"https://github.com/trufflesecurity/test_keys","timestamp":"2022-06-16 10:17:40 -0700 PDT","line":4}}},"SourceID":0,"SourceType":16,"SourceName":"trufflehog - git","DetectorType":2,"DetectorName":"AWS","DecoderName":"PLAIN","Verified":true,"Raw":"AKIAYVP4CIPPERUVIFXG","Redacted":"AKIAYVP4CIPPERUVIFXG","ExtraData":{"account":"595918472158","arn":"arn:aws:iam::595918472158:user/canarytokens.com@@mirux23ppyky6hx3l6vclmhnj","user_id":"AIDAYVP4CIPPJ5M54LRCY"},"StructuredData":null}
...
```

## 4: Scan a GitHub Repo + its Issues and Pull Requests

```bash
trufflehog github --repo=https://github.com/trufflesecurity/test_keys --issue-comments --pr-comments
```

## 5: Scan an S3 bucket for verified keys

```bash
trufflehog s3 --bucket=<bucket name> --results=verified,unknown
```

## 6: Scan S3 buckets using IAM Roles

```bash
trufflehog s3 --role-arn=<iam role arn>
```

## 7: Scan a Github Repo using SSH authentication in Docker

```bash
docker run --rm -v "$HOME/.ssh:/root/.ssh:ro" trufflesecurity/trufflehog:latest git ssh://github.com/trufflesecurity/test_keys
```

## 8: Scan individual files or directories

```bash
trufflehog filesystem path/to/file1.txt path/to/file2.txt path/to/dir
```

## 9: Scan a local git repo

Clone the git repo. For example [test keys](git@github.com:trufflesecurity/test_keys.git) repo.
```bash
$ git clone git@github.com:trufflesecurity/test_keys.git
```

Run trufflehog from the parent directory (outside the git repo).
```bash
$ trufflehog git file://test_keys --results=verified,unknown
```

## 10: Scan GCS buckets for verified secrets

```bash
trufflehog gcs --project-id=<project-ID> --cloud-environment --results=verified,unknown
```

## 11: Scan a Docker image for verified secrets

Use the `--image` flag multiple times to scan multiple images.

```bash
# to scan from a remote registry
trufflehog docker --image trufflesecurity/secrets --results=verified,unknown

# to scan from the local docker daemon
trufflehog docker --image docker://new_image:tag --results=verified,unknown

# to scan from an image saved as a tarball
trufflehog docker --image file://path_to_image.tar --results=verified,unknown
```

## 12: Scan in CI

Set the `--since-commit` flag to your default branch that people merge into (ex: "main"). Set the `--branch` flag to your PR's branch name (ex: "feature-1"). Depending on the CI/CD platform you use, this value can be pulled in dynamically (ex: [CIRCLE_BRANCH in Circle CI](https://circleci.com/docs/variables/) and [TRAVIS_PULL_REQUEST_BRANCH in Travis CI](https://docs.travis-ci.com/user/environment-variables/)). If the repo is cloned and the target branch is already checked out during the CI/CD workflow, then `--branch HEAD` should be sufficient. The `--fail` flag will return an 183 error code if valid credentials are found.

```bash
trufflehog git file://. --since-commit main --branch feature-1 --results=verified,unknown --fail
```

## 13: Scan a Postman workspace

Use the `--workspace-id`, `--collection-id`, `--environment` flags multiple times to scan multiple targets.

```bash
trufflehog postman --token=<postman api token> --workspace-id=<workspace id>
```

## 14: Scan a Jenkins server

```bash
trufflehog jenkins --url https://jenkins.example.com --username admin --password admin
```

## 15: Scan an Elasticsearch server

### Scan a Local Cluster

There are two ways to authenticate to a local cluster with TruffleHog: (1) username and password, (2) service token.

#### Connect to a local cluster with username and password

```bash
trufflehog elasticsearch --nodes 192.168.14.3 192.168.14.4 --username truffle --password hog
```

#### Connect to a local cluster with a service token

```bash
trufflehog elasticsearch --nodes 192.168.14.3 192.168.14.4 --service-token ‘AAEWVaWM...Rva2VuaSDZ’
```

### Scan an Elastic Cloud Cluster

To scan a cluster on Elastic Cloud, you’ll need a Cloud ID and API key.

```bash
trufflehog elasticsearch \
  --cloud-id 'search-prod:dXMtY2Vx...YjM1ODNlOWFiZGRlNjI0NA==' \
  --api-key 'MlVtVjBZ...ZSYlduYnF1djh3NG5FQQ=='
```

## 16. Scan a GitHub Repository for Cross Fork Object References and Deleted Commits

The following command will enumerate deleted and hidden commits on a GitHub repository and then scan them for secrets. This is an alpha release feature.

```bash
trufflehog github-experimental --repo https://github.com/<USER>/<REPO>.git --object-discovery
```

In addition to the normal TruffleHog output, the `--object-discovery` flag creates two files in a new `$HOME/.trufflehog` directory: `valid_hidden.txt` and `invalid.txt`. These are used to track state during commit enumeration, as well as to provide users with a complete list of all hidden and deleted commits (`valid_hidden.txt`). If you'd like to automatically remove these files after scanning, please add the flag `--delete-cached-data`.

**Note**: Enumerating all valid commits on a repository using this method takes between 20 minutes and a few hours, depending on the size of your repository. We added a progress bar to keep you updated on how long the enumeration will take. The actual secret scanning runs extremely fast.

For more information on Cross Fork Object References, please [read our blog post](https://trufflesecurity.com/blog/anyone-can-access-deleted-and-private-repo-data-github).

## 17. Scan Hugging Face

### Scan a Hugging Face Model, Dataset or Space

```bash
trufflehog huggingface --model <model_id> --space <space_id> --dataset <dataset_id>
```

### Scan all Models, Datasets and Spaces belonging to a Hugging Face Organization or User

```bash
trufflehog huggingface --org <orgname> --user <username>
```

(Optionally) When scanning an organization or user, you can skip an entire class of resources with `--skip-models`, `--skip-datasets`, `--skip-spaces` OR a particular resource with `--ignore-models <model_id>`, `--ignore-datasets <dataset_id>`, `--ignore-spaces <space_id>`.

### Scan Discussion and PR Comments

```bash
trufflehog huggingface --model <model_id> --include-discussions --include-prs
```

## 18. Scan stdin Input

```bash
aws s3 cp s3://example/gzipped/data.gz - | gunzip -c | trufflehog stdin
```

# :question: FAQ

- All I see is `🐷🔑🐷  TruffleHog. Unearth your secrets. 🐷🔑🐷` and the program exits, what gives?
  - That means no secrets were detected
- Why is the scan taking a long time when I scan a GitHub org
  - Unauthenticated GitHub scans have rate limits. To improve your rate limits, include the `--token` flag with a personal access token
- It says a private key was verified, what does that mean?
  - Check out our Driftwood blog post to learn how to do this, in short we've confirmed the key can be used live for SSH or SSL [Blog post](https://trufflesecurity.com/blog/driftwood-know-if-private-keys-are-sensitive/)
- Is there an easy way to ignore specific secrets?
  - If the scanned source [supports line numbers](https://github.com/trufflesecurity/trufflehog/blob/d6375ba92172fd830abb4247cca15e3176448c5d/pkg/engine/engine.go#L358-L365), then you can add a `trufflehog:ignore` comment on the line containing the secret to ignore that secrets.

# :newspaper: What's new in v3?

TruffleHog v3 is a complete rewrite in Go with many new powerful features.

- We've **added over 700 credential detectors that support active verification against their respective APIs**.
- We've also added native **support for scanning GitHub, GitLab, Docker, filesystems, S3, GCS, Circle CI and Travis CI**.
- **Instantly verify private keys** against millions of github users and **billions** of TLS certificates using our [Driftwood](https://trufflesecurity.com/blog/driftwood) technology.
- Scan binaries, documents, and other file formats
- Available as a GitHub Action and a pre-commit hook

## What is credential verification?

For every potential credential that is detected, we've painstakingly implemented programmatic verification against the API that we think it belongs to. Verification eliminates false positives. For example, the [AWS credential detector](pkg/detectors/aws/aws.go) performs a `GetCallerIdentity` API call against the AWS API to verify if an AWS credential is active.

# :memo: Usage

TruffleHog has a sub-command for each source of data that you may want to scan:

- git
- github
- gitlab
- docker
- s3
- filesystem (files and directories)
- syslog
- circleci
- travisci
- gcs (Google Cloud Storage)
- postman
- jenkins
- elasticsearch
- stdin
- multi-scan

Each subcommand can have options that you can see with the `--help` flag provided to the sub command:

```
$ trufflehog git --help
usage: TruffleHog git [<flags>] <uri>

Find credentials in git repositories.

Flags:
  -h, --help                Show context-sensitive help (also try --help-long and --help-man).
      --log-level=0         Logging verbosity on a scale of 0 (info) to 5 (trace). Can be disabled with "-1".
      --profile             Enables profiling and sets a pprof and fgprof server on :18066.
  -j, --json                Output in JSON format.
      --json-legacy         Use the pre-v3.0 JSON format. Only works with git, gitlab, and github sources.
      --github-actions      Output in GitHub Actions format.
      --concurrency=20           Number of concurrent workers.
      --no-verification     Don't verify the results.
      --results=RESULTS          Specifies which type(s) of results to output: verified, unknown, unverified, filtered_unverified. Defaults to all types.
      --allow-verification-overlap
                                 Allow verification of similar credentials across detectors
      --filter-unverified   Only output first unverified result per chunk per detector if there are more than one results.
      --filter-entropy=FILTER-ENTROPY
                                 Filter unverified results with Shannon entropy. Start with 3.0.
      --config=CONFIG            Path to configuration file.
      --print-avg-detector-time
                                 Print the average time spent on each detector.
      --no-update           Don't check for updates.
      --fail                Exit with code 183 if results are found.
      --verifier=VERIFIER ...    Set custom verification endpoints.
      --custom-verifiers-only   Only use custom verification endpoints.
      --archive-max-size=ARCHIVE-MAX-SIZE
                                 Maximum size of archive to scan. (Byte units eg. 512B, 2KB, 4MB)
      --archive-max-depth=ARCHIVE-MAX-DEPTH
                                 Maximum depth of archive to scan.
      --archive-timeout=ARCHIVE-TIMEOUT
                                 Maximum time to spend extracting an archive.
      --include-detectors="all"  Comma separated list of detector types to include. Protobuf name or IDs may be used, as well as ranges.
      --exclude-detectors=EXCLUDE-DETECTORS
                                 Comma separated list of detector types to exclude. Protobuf name or IDs may be used, as well as ranges. IDs defined here take precedence over the include list.
      --version             Show application version.
  -i, --include-paths=INCLUDE-PATHS
                                 Path to file with newline separated regexes for files to include in scan.
  -x, --exclude-paths=EXCLUDE-PATHS
                                 Path to file with newline separated regexes for files to exclude in scan.
      --exclude-globs=EXCLUDE-GLOBS
                                 Comma separated list of globs to exclude in scan. This option filters at the `git log` level, resulting in faster scans.
      --since-commit=SINCE-COMMIT
                                 Commit to start scan from.
      --branch=BRANCH            Branch to scan.
      --max-depth=MAX-DEPTH      Maximum depth of commits to scan.
      --bare                Scan bare repository (e.g. useful while using in pre-receive hooks)

Args:
  <uri>  Git repository URL. https://, file://, or ssh:// schema expected.
```

For example, to scan a `git` repository, start with

```
trufflehog git https://github.com/trufflesecurity/trufflehog.git
```

## Configuration

TruffleHog supports defining [custom regex detectors](#regex-detector-alpha)
and multiple sources in a configuration file provided via the `--config` flag.
The regex detectors can be used with any subcommand, while the sources defined
in configuration are only for the `multi-scan` subcommand.

The configuration format for sources can be found on Truffle Security's
[source configuration documentation page](https://docs.trufflesecurity.com/scan-data-for-secrets).

Example GitHub source configuration and [options reference](https://docs.trufflesecurity.com/github#Fvm1I):

```yaml
sources:
- connection:
    '@type': type.googleapis.com/sources.GitHub
    repositories:
    - https://github.com/trufflesecurity/test_keys.git
    unauthenticated: {}
  name: example config scan
  type: SOURCE_TYPE_GITHUB
  verify: true
```

You may define multiple connections under the `sources` key (see above), and
TruffleHog will scan all of the sources concurrently.

## S3

The S3 source supports assuming IAM roles for scanning in addition to IAM users. This makes it easier for users to scan multiple AWS accounts without needing to rely on hardcoded credentials for each account.

The IAM identity that TruffleHog uses initially will need to have `AssumeRole` privileges as a principal in the [trust policy](https://aws.amazon.com/blogs/security/how-to-use-trust-policies-with-iam-roles/) of each IAM role to assume.

To scan a specific bucket using locally set credentials or instance metadata if on an EC2 instance:

```bash
trufflehog s3 --bucket=<bucket-name>
```

To scan a specific bucket using an assumed role:

```bash
trufflehog s3 --bucket=<bucket-name> --role-arn=<iam-role-arn>
```

Multiple roles can be passed as separate arguments. The following command will attempt to scan every bucket each role has permissions to list in the S3 API:

```bash
trufflehog s3 --role-arn=<iam-role-arn-1> --role-arn=<iam-role-arn-2>
```

Exit Codes:

- 0: No errors and no results were found.
- 1: An error was encountered. Sources may not have completed scans.
- 183: No errors were encountered, but results were found. Will only be returned if `--fail` flag is used.

## :octocat: TruffleHog Github Action

### General Usage

```
on:
  push:
    branches:
      - main
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0
    - name: Secret Scanning
      uses: trufflesecurity/trufflehog@main
      with:
        extra_args: --results=verified,unknown
```

In the example config above, we're scanning for live secrets in all PRs and Pushes to `main`. Only code changes in the referenced commits are scanned. If you'd like to scan an entire branch, please see the "Advanced Usage" section below.

### Shallow Cloning

If you're incorporating TruffleHog into a standalone workflow and aren't running any other CI/CD tooling alongside TruffleHog, then we recommend using [Shallow Cloning](https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---depthltdepthgt) to speed up your workflow. Here's an example of how to do it:

```
...
      - shell: bash
        run: |
          if [ "${{ github.event_name }}" == "push" ]; then
            echo "depth=$(($(jq length <<< '${{ toJson(github.event.commits) }}') + 2))" >> $GITHUB_ENV
            echo "branch=${{ github.ref_name }}" >> $GITHUB_ENV
          fi
          if [ "${{ github.event_name }}" == "pull_request" ]; then
            echo "depth=$((${{ github.event.pull_request.commits }}+2))" >> $GITHUB_ENV
            echo "branch=${{ github.event.pull_request.head.ref }}" >> $GITHUB_ENV
          fi
      - uses: actions/checkout@v3
        with:
          ref: ${{env.branch}}
          fetch-depth: ${{env.depth}}
      - uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --results=verified,unknown
...
```

Depending on the event type (push or PR), we calculate the number of commits present. Then we add 2, so that we can reference a base commit before our code changes. We pass that integer value to the `fetch-depth` flag in the checkout action in addition to the relevant branch. Now our checkout process should be much shorter.

### Canary detection

TruffleHog statically detects [https://canarytokens.org/](https://canarytokens.org/).

![image](https://github.com/trufflesecurity/trufflehog/assets/52866392/74ace530-08c5-4eaf-a169-84a73e328f6f)

### Advanced Usage

```yaml
- name: TruffleHog
  uses: trufflesecurity/trufflehog@main
  with:
    # Repository path
    path:
    # Start scanning from here (usually main branch).
    base:
    # Scan commits until here (usually dev branch).
    head: # optional
    # Extra args to be passed to the trufflehog cli.
    extra_args: --log-level=2 --results=verified,unknown
```

If you'd like to specify specific `base` and `head` refs, you can use the `base` argument (`--since-commit` flag in TruffleHog CLI) and the `head` argument (`--branch` flag in the TruffleHog CLI). We only recommend using these arguments for very specific use cases, where the default behavior does not work.

#### Advanced Usage: Scan entire branch

```
- name: scan-push
        uses: trufflesecurity/trufflehog@main
        with:
          base: ""
          head: ${{ github.ref_name }}
          extra_args: --results=verified,unknown
```

## TruffleHog GitLab CI

### Example Usage

```yaml
stages:
  - security

security-secrets:
  stage: security
  allow_failure: false
  image: alpine:latest
  variables:
    SCAN_PATH: "." # Set the relative path in the repo to scan
  before_script:
    - apk add --no-cache git curl jq
    - curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
  script:
    - trufflehog filesystem "$SCAN_PATH" --results=verified,unknown --fail --json | jq
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
```

In the example pipeline above, we're scanning for live secrets in all repository directories and files. This job runs only when the pipeline source is a merge request event, meaning it's triggered when a new merge request is created.

## Pre-commit Hook

TruffleHog can be used in a pre-commit hook to prevent credentials from leaking before they ever leave your computer.

See the [pre-commit hook documentation](PreCommit.md) for more information.

## Regex Detector (alpha)

TruffleHog supports detection and verification of custom regular expressions.
For detection, at least one **regular expression** and **keyword** is required.
A **keyword** is a fixed literal string identifier that appears in or around
the regex to be detected. To allow maximum flexibility for verification, a
webhook is used containing the regular expression matches.

TruffleHog will send a JSON POST request containing the regex matches to a
configured webhook endpoint. If the endpoint responds with a `200 OK` response
status code, the secret is considered verified.

Custom Detectors support a few different filtering mechanisms: entropy, regex targeting the entire match, regex targeting the captured secret,
and excluded word lists checked against the secret (captured group if present, entire match if capture group is not present). Note that if
your custom detector has multiple `regex` set (in this example `hogID`, and `hogToken`), then the filters get applied to each regex. [Here](examples/generic_with_filters.yml) is an example of a custom detector using these filters.

**NB:** This feature is alpha and subject to change.

### Regex Detector Example
[Here](/pkg/custom_detectors/CUSTOM_DETECTORS.md) is how to setup a custom regex detector with verification server.


## :mag: Analyze

TruffleHog supports running a deeper analysis of a credential to view its permissions and the resources it has access to.

```bash
trufflehog analyze
```

# :heart: Contributors

This project exists thanks to all the people who contribute. [[Contribute](CONTRIBUTING.md)].

<a href="https://github.com/trufflesecurity/trufflehog/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=trufflesecurity/trufflehog" />
</a>

# :computer: Contributing

Contributions are very welcome! Please see our [contribution guidelines first](CONTRIBUTING.md).

We no longer accept contributions to TruffleHog v2, but that code is available in the `v2` branch.

## Adding new secret detectors

We have published some [documentation and tooling to get started on adding new secret detectors](hack/docs/Adding_Detectors_external.md). Let's improve detection together!

# Use as a library

Currently, trufflehog is in heavy development and no guarantees can be made on
the stability of the public APIs at this time.

# License Change

Since v3.0, TruffleHog is released under a AGPL 3 license, included in [`LICENSE`](LICENSE). TruffleHog v3.0 uses none of the previous codebase, but care was taken to preserve backwards compatibility on the command line interface. The work previous to this release is still available licensed under GPL 2.0 in the history of this repository and the previous package releases and tags. A completed CLA is required for us to accept contributions going forward.
