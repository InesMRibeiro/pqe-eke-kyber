# EKE-Kyber: Authenticated Post-Quantum Key Exchange

This project implements an authenticated post-quantum key exchange protocol by integrating **CRYSTALS-Kyber** into the **Encrypted Key Exchange (EKE)** framework. 

The primary goal is to provide a communication channel that is secure against quantum-capable adversaries while preventing Man-in-the-Middle (MitM) attacks through password-based authentication.

## Overview
Standard Key Encapsulation Mechanisms (KEMs) like Kyber provide strong confidentiality but do not inherently authenticate the participants, leaving them vulnerable to active attacks. This project addresses this by using a pre-shared password to encrypt and verify the exchange of public keys.



## Key Features
* **Post-Quantum Security:** Utilizes CRYSTALS-Kyber, a lattice-based KEM standardized by NIST.
* **Implicit Authentication:** Employs the EKE paradigm to ensure only parties with the correct password can recover the public key and establish a shared secret.
* **Authenticated Encryption:** Uses **AES-256-GCM** to protect the public key material during transmission.
* **Key Derivation:** Implements **PBKDF2** with a salt to derive symmetric keys from low-entropy passwords.

## Repository Structure
The project is organized as follows:

* **`src/`**: Contains the C source code for the protocol.
    * Includes the [**PQ-Crystals**](https://github.com/pq-crystals/kyber) for Kyber.
    * Logic for password-based key derivation and the Alice-Bob simulation.
* **`report/`**: Technical documentation detailing the project's background, mathematical structure of Kyber, and implementation details.


---

**Author:** Inês Martins Ribeiro 
**Course:** Network and Computer Security
