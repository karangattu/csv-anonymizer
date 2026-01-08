# CSV Anonymizer

A web application for anonymizing sensitive data in CSV files using HMAC-SHA256 hashing.

![Tests](https://github.com/karangattu/csv-anonymizer/actions/workflows/test.yml/badge.svg)

## Features

- **Upload CSV files** - Drag & drop or browse to upload
- **Select columns** - Choose which columns to anonymize
- **Secure hashing** - Uses HMAC-SHA256 with your secret key
- **Consistent results** - Same value + key = same hash (useful for joining data)
- **Download results** - Get anonymized CSV with `-anonymized` suffix

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Usage

1. Upload a CSV file
2. Select columns containing sensitive data
3. Enter a secret key (save this if you need consistent hashing across files)
4. Click "Anonymize" and download the result

## Testing

```bash
pytest test_app.py -v
```

## Tech Stack

- Flask
- Pandas
- HMAC-SHA256 for anonymization


## Live version of the app

A live version of the app is available at https://csv-anonymizer-dwk5.onrender.com/