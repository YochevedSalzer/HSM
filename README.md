# HSM: High-Performance Hardware Security Module

This repository, **HSM**, is a high-performance C++ cryptography library designed for secure data encryption, decryption, and authentication within hardware environments. Developed collaboratively under the mentorship of Mobileye, this project integrates multithreading, GPU acceleration with Intel oneAPI, and gRPC for authenticated communication. The module is built for flexibility, supporting both SYCL-enabled and CPU-only environments, and can be deployed across various hardware setups, including Raspberry Pi.

## Features

### Main Function Points
- **Secure Data Encryption and Decryption**: Supports symmetric and asymmetric encryption, as well as digital signatures.
- **Multithreading Support**: Optimized for concurrent operations to enhance performance.
- **GPU Acceleration with Intel oneAPI**: Uses SYCL and Intel oneAPI to enable high-speed cryptographic computations on GPU.
- **gRPC Communication**: Facilitates encrypted and authenticated communication with hardware components.

### Technology Stack
- **C++**: Core cryptographic functionalities and library implementation.
- **Intel oneAPI & SYCL**: Accelerates computations on supported GPUs.
- **gRPC**: Enables secure, authenticated communication between server and hardware.

## Project Overview

This project, developed in collaboration with a team and Mobileye mentors, aims to create a flexible and high-performance **Hardware Security Module (HSM)** for secure vehicle communication. The HSM includes support for:
- Symmetric and asymmetric encryption algorithms.
- Digital signatures.
- PKCS#11 standard-based architecture, adapted to fit specific project requirements.
  
The HSM provides encryption and authentication services to vehicle components in a simulated environment, enabling secure information exchange. It is compatible with SYCL and CPU environments, allowing deployment on various hardware setups. Although developed and tested on a Raspberry Pi, it is adaptable to other platforms, including software-only environments.

