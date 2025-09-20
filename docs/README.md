# SecretSnipe Documentation

Welcome to the comprehensive documentation for SecretSnipe, an enterprise-grade secret scanning and monitoring solution.

## 📚 Documentation Overview

This documentation provides everything you need to deploy, configure, use, and extend SecretSnipe for your organization's security needs.

### 🚀 Quick Start
- [Installation Guide](./user-guides/installation.md)
- [First Scan](./user-guides/first-scan.md)
- [Dashboard Setup](./user-guides/dashboard-setup.md)

### ⚙️ Configuration
- [Environment Variables](./configuration/environment-variables.md)
- [Docker Configuration](./configuration/docker-setup.md)
- [Database Setup](./configuration/database-configuration.md)
- [Network Share Integration](./configuration/network-shares.md)

### 🔧 API Reference
- [REST API](./api/rest-api.md)
- [Webhook Integration](./api/webhooks.md)
- [Authentication](./api/authentication.md)

### 🛠️ Development
- [Architecture Overview](./development/architecture.md)
- [Adding Detectors](./development/adding-detectors.md)
- [Testing Guide](./development/testing.md)
- [Contributing](./development/contributing.md)

### 🔍 Troubleshooting
- [Common Issues](./troubleshooting/common-issues.md)
- [Performance Tuning](./troubleshooting/performance.md)
- [Log Analysis](./troubleshooting/logs.md)
- [Database Issues](./troubleshooting/database.md)

### 📖 User Guides
- [Advanced Scanning](./user-guides/advanced-scanning.md)
- [Continuous Monitoring](./user-guides/continuous-monitoring.md)
- [Report Generation](./user-guides/reports.md)
- [Security Best Practices](./user-guides/security.md)

## 🎯 Key Features

### Multi-Format File Support
- **Code Files**: Python, JavaScript, TypeScript, Java, C/C++, PHP, Ruby, Go, Rust
- **Documents**: PDF, Word, Excel, PowerPoint
- **Images**: JPG, PNG, BMP, TIFF (with OCR)
- **Archives**: ZIP, TAR, GZ (recursive extraction)
- **Configuration**: JSON, XML, YAML, INI, ENV files

### Advanced Detection
- **15+ Built-in Detectors**: API keys, passwords, tokens, certificates
- **Custom Signatures**: Regex-based pattern matching
- **OCR Support**: Text extraction from images
- **Context Analysis**: False positive reduction through intelligent analysis

### Enterprise Features
- **PostgreSQL Backend**: Scalable data storage
- **Redis Caching**: High-performance caching layer
- **Docker Deployment**: Containerized for easy deployment
- **Webhook Integration**: Real-time notifications
- **Audit Logging**: Complete audit trail
- **Role-Based Access**: Multi-user support

### Monitoring & Alerting
- **Continuous Monitoring**: Real-time file system watching
- **Scheduled Scans**: Automated periodic scanning
- **Teams Integration**: Microsoft Teams webhook notifications
- **Dashboard**: Web-based monitoring interface
- **Performance Metrics**: Detailed scanning statistics

## 🏗️ Architecture

SecretSnipe follows a modular architecture designed for scalability and maintainability:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   File System   │───▶│   Scanner Core  │───▶│   Detectors     │
│   (Local/CIFS)  │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │     Redis       │    │   Webhooks      │
│   Database      │    │     Cache       │    │   (Teams/Slack) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                ▲                        │
                                │                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Dashboard     │◀───│   API Layer     │    │   Reports       │
│   (Dash/Flask)  │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📊 Performance Characteristics

- **File Processing**: Up to 1000 files/minute
- **OCR Accuracy**: 95%+ for clear text in images
- **False Positive Rate**: <5% with context analysis
- **Memory Usage**: 512MB baseline, 2GB with OCR
- **Database Growth**: ~1GB per 100K files scanned

## 🔐 Security Considerations

- **Secret Masking**: Automatic masking in logs and UI
- **Encrypted Storage**: Optional encryption for sensitive data
- **Access Control**: Role-based permissions
- **Audit Trail**: Complete logging of all operations
- **Network Security**: TLS encryption for all communications

## 📈 Roadmap

See [ROADMAP.md](../ROADMAP.md) for upcoming features and planned improvements.

## 🤝 Support

- **Issues**: [GitHub Issues](https://github.com/TimKenobi/Secret_Snipe/issues)
- **Discussions**: [GitHub Discussions](https://github.com/TimKenobi/Secret_Snipe/discussions)
- **Wiki**: [GitHub Wiki](https://github.com/TimKenobi/Secret_Snipe/wiki)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.

---

*Last updated: September 19, 2025*