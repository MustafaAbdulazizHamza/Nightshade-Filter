# Nightshade Filter
---
## Overview
Nightshade is an advanced phishing detection API that leverages state-of-the-art DeBERTa transformer models to analyze both email subjects and bodies. Named after the deadly nightshade plant from the Addams Family aesthetic, this system provides robust protection against phishing attacks through secure, authenticated endpoints.

Key Features:
- JWT-based authentication for secure API access

- Dual-model architecture analyzing both subject lines and email bodies

- GPU acceleration support for fast inference

- HTTPS/TLS encryption for secure communications

- Batch processing support for multiple emails

- High accuracy using fine-tuned DeBERTa models

 YAML configuration for easy deployment management
## Models
Two fine-tuned DeBERTa models were employed for email classification, both trained on the Phishing Email Curated Datasets from Zenodo. The first model was trained for body classification and achieved an F1 score of 0.99, while the second model was trained for subject line classification with an F1 score of 0.95.

## Quick Start
### Prerequisites
1. Python 3.11+
2. CUDA-compatible GPU (optional, but recommended)
3. OpenSSL (for HTTPS certificate generation)
### Installation
1. Clone the repository:
```bash
git clone https://github.com/MustafaAbdulazizHamza/Nightshade-Filter.git
cd Nightshade-Filter
```
2. Create virtual environment:
```bash
python -m venv env
source env/bin/activate  # On Windows: env\Scripts\activate
```
3. Install dependencies:
```
pip install -r requirements.txt
```
4. Generate SSL certificates
```bash
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```
5. Configure the application by editing the config.yaml file
```yaml
SECRET_KEY: "r25BdIag7v7GRW0CXCntF4KRQ1JuGgNg3mM6imXSNaY"
ALGORITHM: "HS256"
TOKEN_EXPIRATION_HOURS: 24
USERNAME: "admin"
PASSWORD: "admin"
MaxNumEmails: 100
HOST: "0.0.0.0"
PORT: 8888
SSL_CERTFILE: "cert.pem"
SSL_KEYFILE: "key.pem"
```
6. Run the application
```bash
uvicorn NightshadeFilter:app
```
## Notes
- API documentation is available at the /docs endpoint.
- The fine-tuned DeBERTa models are available on Hugging Face in my account at [this link](https://huggingface.co/mustafaAbdulazizHamza)
