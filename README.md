# Follina (CVE-2022-30190) Mitigation Tool

A comprehensive mitigation and monitoring solution for the Microsoft Office MSDT Follina vulnerability (CVE-2022-30190).

## Features

1. **MSDT Protocol Control**
   - Enable/Disable MSDT protocol handler
   - Real-time status monitoring

2. **MS Office Security Settings**
   - Monitor VBA macro settings
   - Check internet content blocking settings
   - Support for multiple Office versions

3. **File Scanner**
   - Scan files for Follina exploit indicators
   - MD5 hash verification
   - Detailed threat reporting

4. **Real-time Monitoring**
   - Monitor MSDT process calls
   - Track suspicious activities
   - Process information logging

## Tech Stack

### Backend
- **Python 3.7+**
  - Flask (Web Framework)
  - Watchdog (File System Monitoring)
  - psutil (Process Management)
  - winreg (Registry Management)
  - olefile (OLE File Analysis)

### Frontend
- **React.js**
  - Material-UI Components
  - Axios (HTTP Client)
  

### Security Components
- **Core Security**
  - Windows Registry API
  - OLE Object Analysis
  - MD5 Hashing
  - Base64 Detection/Decoding

### System Integration
- **Windows Components**
  - MSDT Protocol Handler
  - Windows Registry
  - Process Management
  - File System Events

### Development Tools
- **Environment**
  - Visual Studio Code
  - Python Virtual Environment
  - Git Version Control
  - npm/yarn (Frontend Package Management)

## Requirements

- Windows 10/11
- Python 3.7+
- Microsoft Office (for Office settings monitoring)
- Administrative privileges (for MSDT control)

## Installation

1. Clone the repository:

```bash
git clone [repository-url]

```

2. Create a virtual environment (recommended):

```bash
python -m venv venv
.\venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

1. Run the application:

```bash
python follina_mitigation.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

3. Use the web interface to:
   - Control MSDT protocol
   - Monitor Office security settings
   - Scan suspicious files
   - Enable real-time monitoring

## Security Recommendations

1. Keep Windows and Office up to date
2. Enable Office security features:
   - Set VBA macro warnings to highest level
   - Enable content execution blocking from internet
3. Use the real-time monitoring feature
4. Regularly scan downloaded files
5. Keep MSDT disabled when not needed


## License

MIT License

## Disclaimer

This tool is for defensive purposes only. The authors are not responsible for any misuse or damage caused by this tool. 
