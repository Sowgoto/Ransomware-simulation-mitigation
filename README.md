# Ransomware Simulation and Mitigation

⚠️ **Educational Use Only**

This project is a controlled cybersecurity simulation created for academic purposes. It demonstrates ransomware-like file encryption behavior, monitoring, detection, mitigation, and backup restoration inside a virtual machine.

This project must only be executed in an isolated lab environment or virtual machine. Do not run it on personal, production, or third-party systems.

## Overview

Ransomware is a type of malware that encrypts files and demands payment for decryption. This project simulates ransomware behavior in a safe and controlled virtualized environment.

The goal of this project is to understand how ransomware operates and how monitoring, detection, mitigation, and recovery techniques can reduce damage.

## Features

- Controlled ransomware simulation using Python
- File encryption and decryption simulation
- Real-time file monitoring
- Suspicious activity detection
- Process-based mitigation
- Backup-based file restoration
- Logging and alert generation
- Safe testing inside a virtual machine

## Project Components

### 1. Ransomware Simulation

The `ransomware_sim.py` file simulates ransomware-like encryption behavior on test files in a controlled directory.

### 2. Monitoring

The `monitoring.py` file monitors file system activity such as file creation, modification, deletion, and movement.

### 3. Detection

The `detection.py` file analyzes monitored events and detects suspicious activity.

### 4. Mitigation

The `mitigation.py` file responds to suspicious activity by stopping suspicious behavior and restoring files from backup.

## Safe Usage

Run this project only inside a virtual machine using test files.

Do not run this project on:

- Personal computers with important files
- Production systems
- Shared systems
- Third-party machines
- University systems without permission
