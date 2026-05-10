# Peekwatch

A real-time system monitoring and threat detection tool for Windows, Linux, and macOS.

## Features

- 🔍 **Real-time Process Monitoring** - Track running processes and system activity
- 🛡️ **Threat Detection** - Identify suspicious activities and potential security risks
- 📊 **System Metrics** - Monitor CPU, memory, network, and disk usage
- 🔔 **Alert System** - Get notified when threats are detected
- 🌐 **Cross-Platform** - Works on Windows, Linux, and macOS

## Requirements

- Python 3.8+
- Git

## Installation

### Windows

# Clone the repository
git clone https://github.com/AceARG/Peekwatch.git
cd Peekwatch

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate

# Install dependencies
pip install -r requirements.txt

# Run
python main.py

### Linux

# Clone the repository
git clone https://github.com/AceARG/Peekwatch.git
cd Peekwatch

# Install dependencies
pip3 install -r requirements.txt

# Run
python3 main.py

### macOS

# Clone the repository
git clone https://github.com/AceARG/Peekwatch.git
cd Peekwatch

# Install dependencies
pip3 install -r requirements.txt

# Run
python3 main.py

## Usage

# Basic run
python main.py

# With specific config
python main.py --config config.yaml

# Help
python main.py --help

## Configuration

Edit `config.json` or `config.yaml` to customize:
- Alert thresholds
- Monitoring intervals
- Notification settings

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
