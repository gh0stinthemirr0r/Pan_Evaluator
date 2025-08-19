# PanOS Evaluator

A comprehensive GUI application for analyzing and optimizing Palo Alto Networks firewall security policies. The tool provides detailed analysis of rule shadowing, merge opportunities, and usage patterns to help security administrators optimize their firewall configurations.

![Screenshot 01]([[https://raw.githubusercontent.com/gh0stinthemirr0r/pan_evaluator/main/sceenshots/screenshot01.png](https://github.com/gh0stinthemirr0r/pan_evaluator/blob/main/sceenshots/screenshot01.png))](https://github.com/gh0stinthemirr0r/pan_evaluator/blob/main/sceenshots/screenshot01.png?raw=true)

![Screenshot 02]([https://raw.githubusercontent.com/gh0stinthemirr0r/pan_evaluator/main/sceenshots/screenshot02.png](https://github.com/gh0stinthemirr0r/pan_evaluator/blob/main/sceenshots/screenshot02.png))

## Features

### 🔍 **Dual Analysis Modes**
- **API Mode**: Direct integration with Palo Alto Networks firewalls via REST API
- **CSV Import Mode**: Import exported policy data from firewall for offline analysis

### 📊 **Comprehensive Analysis**
- **Rule Shadowing Detection**: Identifies rules that are completely blocked by earlier rules
- **Merge Recommendations**: Suggests rules that could be consolidated based on similar characteristics
- **Usage Analytics**: Analyzes hit counts to identify unused or underutilized rules
- **Position Tracking**: Shows exact rule positions for easy reference

### 📈 **Advanced Analytics Dashboard**
- **Overview Tab**: System-wide metrics and summary statistics
- **Analysis Tab**: Detailed rule-by-rule analysis with recommendations
- **Export Capabilities**: CSV and XLSX export with both overview and analysis data

### 🎯 **Smart Recommendations**
- **Manual Review Required**: All recommendations explicitly note the need for human review
- **Confidence Scoring**: Merge suggestions include confidence levels
- **Contextual Reasoning**: Provides explanations for why recommendations are made

## Installation

### Prerequisites
- Python 3.8 or higher
- Palo Alto Networks firewall with API access (for API mode)

### Dependencies
```bash
pip install pandas tabulate openpyxl requests
```

### Optional Dependencies
For API mode functionality:
```bash
pip install pan-os-python setuptools
```

## Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/pan_evaluator.git
   cd pan_evaluator
   ```

2. **Run the application**
   ```bash
   python evaluator.py
   ```

3. **Choose your analysis mode**
   - **API Mode**: Enter firewall details and API key
   - **CSV Mode**: Import exported policy data

## Usage Guide

### API Mode
1. Enter your firewall's IP address or hostname
2. Provide your API key
3. Select the appropriate VSYS (if using multi-VSYS)
4. Click "Test API Connection" to verify connectivity
5. Click "Run Analysis" to start the evaluation

### CSV Import Mode
1. Click "Choose CSV File" to select your exported policy data
2. The application will automatically parse the CSV format
3. Click "Run Analysis" to process the imported data

### Understanding Results

#### Overview Tab
- **System Information**: Analysis source, date, total rules
- **Rule Actions**: Breakdown of allow vs deny rules
- **Hit Count Analytics**: Usage patterns and zero-hit rules
- **Diversity Metrics**: Unique applications, services, zones
- **Analysis Results**: Shadowed rules and merge opportunities
- **Recommendations**: Summary of actions requiring review

#### Analysis Tab
- **Complete Rule Data**: All 23 columns from the original export
- **Recommendations Column**: Specific suggestions for each rule
- **Position Information**: Exact rule positions for easy reference

### Export Options
- **CSV Export**: Single file with both overview and analysis sections
- **XLSX Export**: Excel file with separate sheets for overview and analysis

## Configuration

The application automatically saves your settings in `evaluator.conf`:
- API URL and key
- VSYS selection
- Output directory
- Window geometry
- CSV file path
- Analysis mode preference

## API Requirements

### Firewall Configuration
- API access enabled
- Valid API key with appropriate permissions
- Network connectivity to the firewall

### API Key Generation
```bash
# SSH to your firewall and generate a new API key
ssh admin@your-firewall-ip
request api-key generate
```

## CSV Import Format

The application expects CSV files exported from Palo Alto Networks firewalls with the following columns:
- Name, Position, Description, Tags, From Zone, To Zone, Source, Destination
- Application, Service, Action, Log Setting, Profile Setting
- Hit Count, Last Hit, Creation Time, Modification Time
- And more...

## Troubleshooting

### Common Issues

**API Connection Failures**
- Verify firewall reachability
- Check API key validity
- Ensure API access is enabled on the firewall

**Import Errors**
- Verify CSV format matches expected structure
- Check file encoding (UTF-8 recommended)
- Ensure all required columns are present

**Dependency Issues**
- Install missing packages: `pip install -r requirements.txt`
- For Python 3.13+: Install setuptools: `pip install setuptools`

### Test Scripts
The project includes several test scripts for troubleshooting:
- `test_network.py`: Network connectivity testing
- `test_panos_detailed.py`: Detailed API testing
- `test_api_key_format.py`: API key validation

## Security Considerations

- API keys are stored locally in `evaluator.conf`
- No data is transmitted to external services
- All analysis is performed locally
- Export files contain sensitive policy information

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Create an issue on GitHub
- Check the troubleshooting section
- Review the test scripts for debugging

## Changelog

### v1.0.0
- Initial release with dual-mode analysis
- GUI interface with tabbed results
- Comprehensive rule analysis
- Export capabilities (CSV/XLSX)
- Configuration persistence
- API connectivity testing

---

**Note**: This tool is designed to assist with policy optimization but requires manual review before implementing any changes. Always test recommendations in a non-production environment first.
