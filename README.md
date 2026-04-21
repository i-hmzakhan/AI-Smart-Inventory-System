# Aegis-AI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-fidelity malware analysis system that performs automated feature extraction and heuristic triage on Windows Portable Executable (PE) binaries using machine learning.

## What the Project Does

Aegis-AI is an AI-powered malware detection platform that bridges a PHP-based web management layer with a Python-based inference engine. The system analyzes Windows PE files by extracting 33-dimensional feature vectors from binary headers, sections, and import tables, then uses a trained LightGBM classifier to predict malware probability. Results are stored in a MariaDB database with forensic integrity, allowing manual overrides and deduplication based on SHA-256 hashes.

Key components:
- **Binary Ingestion**: Secure upload and quarantine of PE files
- **Feature Extraction**: Static analysis using pefile library to extract telemetry
- **AI Classification**: LightGBM model processing 33 features including entropy, header characteristics, and section analysis
- **Forensic Storage**: Relational database with JSON feature storage and referential integrity
- **Web Interface**: PHP-based dashboard for uploads, reports, and manual verdicts

## Why the Project is Useful

- **Automated Triage**: Quickly classify suspicious files without execution, reducing risk
- **High-Accuracy Detection**: Uses entropy and structural features that are hard for malware authors to obfuscate
- **Forensic Integrity**: Maintains complete analysis history with deduplication and manual override capabilities
- **Security-First Design**: Files are quarantined and deleted post-analysis, with zero-persistence sessions
- **Scalable Architecture**: Supports batch processing and can be extended for additional file types

## How Users Can Get Started

### Prerequisites

- Python 3.11 or higher
- PHP 8.2 or higher
- MariaDB (or MySQL) server
- XAMPP (for Apache/PHP stack) or similar web server setup

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/i-hmzakhan/Aegis-AI.git
   cd Aegis-AI
   ```

2. **Set up Python environment:**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # On Windows
   pip install pefile joblib numpy pandas scikit-learn lightgbm
   ```

3. **Configure the database:**
   - Install and start MariaDB
   - Create database `malware_db`
   - Create user `your_user` with password `password`
   - Grant SELECT, INSERT, UPDATE permissions on `malware_db.*`

4. **Set up web server:**
   - Configure Apache/PHP to serve the `api/` directory
   - Ensure PHP has PDO MySQL extension enabled
   - Update paths in `api/process_scan.php` if necessary

5. **Place model files:**
   - Ensure `ai_model/malware_model_v3.pkl` and `ai_model/scaler_v3.pkl` are present
   - These contain the trained LightGBM model and feature scaler

### Usage

1. **Access the web interface:**
   - Navigate to your configured web server URL
   - Log in with appropriate credentials (default user setup required)

2. **Upload and analyze files:**
   - Use the upload form to submit PE files
   - The system will automatically extract features and classify
   - View results in the reports dashboard

3. **Manual analysis:**
   - Access admin panel for manual verdict overrides
   - Review feature extractions and AI predictions

### Example API Usage

The system processes files through the web interface, but the core AI engine can be used programmatically:

```python
from triage import extract_33_features
import joblib

# Load model and scaler
model = joblib.load('ai_model/malware_model_v3.pkl')
scaler = joblib.load('ai_model/scaler_v3.pkl')

# Extract features from a PE file
features = extract_33_features('path/to/file.exe')
if features is not None:
    scaled_features = scaler.transform(features)
    probability = model.predict_proba(scaled_features)[0][1]
    print(f"Malware probability: {probability:.3f}")
```

## Where Users Can Get Help

- **Issues**: Report bugs or request features on [GitHub Issues](https://github.com/i-hmzakhan/Aegis-AI/issues)
- **Discussions**: Join community discussions on [GitHub Discussions](https://github.com/i-hmzakhan/Aegis-AI/discussions)
- **Documentation**: See inline code comments and database schema for technical details

## Who Maintains and Contributes

**Maintainer**: Hamza Khan (BSAI, UEAS Swat)

**Contributing**:
- Fork the repository
- Create a feature branch
- Submit pull requests with clear descriptions
- Follow the existing code style and security practices

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines (if available).

Project Scope: Database Management Systems & AI Integration
