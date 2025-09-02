#!/usr/bin/env python3
"""
Example script demonstrating LLM log collection functionality
"""

from llm_scanner import LLMSoftwareDetector
import sys

def main():
    print("LLM Log Collection Example")
    print("=" * 40)
    
    # Initialize the detector
    detector = LLMSoftwareDetector()
    
    # Option 1: Collect logs directly (without running detection scan)
    print("\n1. Collecting logs directly...")
    try:
        archive_path = detector.collect_logs("zip")
        print(f"✓ Log archive created: {archive_path}")
    except Exception as e:
        print(f"✗ Error collecting logs: {e}")
    
    # Option 2: Run detection scan first, then collect logs
    print("\n2. Running detection scan and collecting logs...")
    try:
        results = detector.run_scan()
        
        if results['summary']['software_found']:
            print(f"Found software: {', '.join(results['summary']['software_found'])}")
            archive_path = detector.collect_logs("zip")
            print(f"✓ Log archive created: {archive_path}")
        else:
            print("No LLM software detected")
    except Exception as e:
        print(f"✗ Error during scan and log collection: {e}")
    
    # Option 3: Collect logs in 7z format (if available)
    print("\n3. Collecting logs in 7z format...")
    try:
        archive_path = detector.collect_logs("7z")
        print(f"✓ Log archive created: {archive_path}")
    except Exception as e:
        print(f"✗ Error collecting logs in 7z format: {e}")

if __name__ == "__main__":
    main()
