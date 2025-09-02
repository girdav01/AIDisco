#!/usr/bin/env python3
"""
Example usage script for LLM Software Detection Scanner
Demonstrates basic usage and result processing
"""

import json
import subprocess
import sys
from pathlib import Path

def run_scanner():
    """Run the LLM scanner and process results"""
    print("Running LLM Software Detection Scanner...")
    print("=" * 50)

    try:
        # Run the scanner
        result = subprocess.run([
            sys.executable, "llm_scanner.py", 
            "--output", "example_scan_results.json",
            "--verbose"
        ], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"Scanner failed with error: {result.stderr}")
            return

        # Load and process results
        with open("example_scan_results.json", 'r') as f:
            scan_results = json.load(f)

        print("\n" + "=" * 50)
        print("SCAN RESULTS SUMMARY")
        print("=" * 50)

        # System information
        sys_info = scan_results.get("system_info", {})
        print(f"System: {sys_info.get('os')} {sys_info.get('release')}")
        print(f"Architecture: {sys_info.get('architecture')}")
        print(f"Scan Time: {scan_results.get('scan_timestamp')}")

        # Detection summary
        summary = scan_results.get("summary", {})
        print(f"\nTotal Detections: {summary.get('total_detections', 0)}")
        print(f"Software Found: {', '.join(summary.get('software_found', []))}")
        print(f"High Confidence: {summary.get('high_confidence', 0)}")
        print(f"Medium Confidence: {summary.get('medium_confidence', 0)}")

        # Detailed detections
        detections = scan_results.get("detections", [])
        if detections:
            print("\n" + "-" * 30)
            print("DETAILED DETECTIONS")
            print("-" * 30)

            for i, detection in enumerate(detections, 1):
                print(f"{i}. {detection['software']}")
                print(f"   Type: {detection['detection_type']}")
                print(f"   Value: {detection['value']}")
                print(f"   Confidence: {detection['confidence']}")
                if detection.get('path'):
                    print(f"   Path: {detection['path']}")
                print()

        # SIGMA rule matches
        sigma_matches = scan_results.get("sigma_matches", [])
        if sigma_matches:
            print("-" * 30)
            print("SIGMA RULE MATCHES")
            print("-" * 30)

            for i, match in enumerate(sigma_matches, 1):
                print(f"{i}. {match['rule_title']}")
                print(f"   Rule ID: {match['rule_id']}")
                print(f"   Level: {match['level']}")
                print(f"   Detection: {match['detection']['software']} - {match['detection']['type']}")
                print()

        # Recommendations
        print("-" * 30)
        print("RECOMMENDATIONS")
        print("-" * 30)

        if summary.get('total_detections', 0) == 0:
            print("• No LLM software detected on this system")
        else:
            print("• Review detected LLM installations for compliance")
            print("• Monitor network activity on detected ports")
            print("• Consider implementing additional security controls")
            if sigma_matches:
                print("• Investigate SIGMA rule matches for potential security concerns")

        print(f"\nDetailed results saved to: example_scan_results.json")

    except FileNotFoundError:
        print("Error: llm_scanner.py not found in current directory")
        print("Make sure you're running this script from the scanner directory")
    except json.JSONDecodeError as e:
        print(f"Error parsing scan results: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import psutil
        import yaml
        print("✓ All dependencies are installed")
        return True
    except ImportError as e:
        print(f"✗ Missing dependency: {e}")
        print("Please install dependencies with: pip install -r requirements.txt")
        return False

def main():
    print("LLM Software Detection Scanner - Example Usage")
    print("=" * 50)

    # Check dependencies
    if not check_dependencies():
        return

    # Check if scanner exists
    if not Path("llm_scanner.py").exists():
        print("Error: llm_scanner.py not found")
        print("Please ensure you're in the correct directory")
        return

    # Check if SIGMA rules exist
    sigma_dir = Path("sigma_rules")
    if sigma_dir.exists():
        rule_count = len(list(sigma_dir.glob("*.yml")))
        print(f"✓ Found {rule_count} SIGMA rules")
    else:
        print("⚠ SIGMA rules directory not found")

    print()

    # Run the scanner
    run_scanner()

if __name__ == "__main__":
    main()
