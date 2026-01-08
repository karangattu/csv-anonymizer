import os
import csv
import hmac
import hashlib
import uuid
from flask import Flask, render_template, request, jsonify, send_file
import pandas as pd
import chardet
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Use /tmp for uploads in production (Render), local folder for development
if os.environ.get('RENDER'):
    app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
else:
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Store file info temporarily (in production, use a database or session)
file_storage = {}


def detect_encoding(filepath):
    """Detect file encoding using chardet."""
    with open(filepath, 'rb') as f:
        # Read first 10KB for detection
        raw_data = f.read(10240)
    result = chardet.detect(raw_data)
    encoding = result.get('encoding', 'utf-8')
    # Handle common encoding aliases
    if encoding and encoding.lower() in ['ascii', 'iso-8859-1', 'latin-1']:
        return encoding
    return encoding or 'utf-8'


def detect_delimiter(filepath, encoding):
    """Detect CSV delimiter using csv.Sniffer."""
    try:
        with open(filepath, 'r', encoding=encoding, errors='replace') as f:
            # Read first 8KB for sniffing
            sample = f.read(8192)
        sniffer = csv.Sniffer()
        dialect = sniffer.sniff(sample, delimiters=',;\t|')
        return dialect.delimiter
    except csv.Error:
        # Default to comma if detection fails
        return ','


def read_csv_robust(filepath):
    """Read CSV with robust encoding and delimiter detection."""
    # Detect encoding
    encoding = detect_encoding(filepath)
    
    # Detect delimiter
    delimiter = detect_delimiter(filepath, encoding)
    
    # Read CSV with detected parameters
    df = pd.read_csv(
        filepath,
        encoding=encoding,
        sep=delimiter,
        on_bad_lines='warn',  # Skip malformed rows
        encoding_errors='replace',  # Replace undecodable chars
        skipinitialspace=True,  # Handle spaces after delimiter
        dtype=str,  # Read all columns as strings initially
    )
    
    # Strip BOM from column names if present
    df.columns = [col.lstrip('\ufeff').strip() for col in df.columns]
    
    return df, encoding, delimiter


def anonymize_value(value, secret_key):
    """Anonymize a single value using HMAC-SHA256."""
    if pd.isna(value) or value == '' or str(value).strip() == '':
        return value
    return hmac.new(
        secret_key.encode(),
        str(value).encode(),
        hashlib.sha256
    ).hexdigest()[:16]


@app.route('/')
def index():
    """Serve the main page."""
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle CSV upload and return column names."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.lower().endswith('.csv'):
        return jsonify({'error': 'Only CSV files are allowed'}), 400
    
    try:
        # Generate unique ID for this upload
        file_id = str(uuid.uuid4())
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}_{filename}")
        
        # Save the file
        file.save(filepath)
        
        # Validate file is not empty
        if os.path.getsize(filepath) == 0:
            os.remove(filepath)
            return jsonify({'error': 'File is empty'}), 400
        
        # Read CSV with robust detection
        df, encoding, delimiter = read_csv_robust(filepath)
        
        # Validate we have data
        if df.empty:
            os.remove(filepath)
            return jsonify({'error': 'CSV file has no data rows'}), 400
        
        if len(df.columns) == 0:
            os.remove(filepath)
            return jsonify({'error': 'CSV file has no columns'}), 400
        
        columns = df.columns.tolist()
        
        # Store file info including detected parameters
        file_storage[file_id] = {
            'filepath': filepath,
            'original_filename': filename,
            'columns': columns,
            'encoding': encoding,
            'delimiter': delimiter
        }
        
        return jsonify({
            'file_id': file_id,
            'columns': columns,
            'row_count': len(df),
            'encoding': encoding,
            'delimiter': 'comma' if delimiter == ',' else 
                        'semicolon' if delimiter == ';' else
                        'tab' if delimiter == '\t' else
                        'pipe' if delimiter == '|' else delimiter
        })
    
    except pd.errors.EmptyDataError:
        return jsonify({'error': 'CSV file is empty or invalid'}), 400
    except Exception as e:
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500


@app.route('/anonymize', methods=['POST'])
def anonymize():
    """Anonymize selected columns with the provided hash key."""
    data = request.json
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    file_id = data.get('file_id')
    columns_to_anonymize = data.get('columns', [])
    secret_key = data.get('secret_key', '')
    
    if not file_id or file_id not in file_storage:
        return jsonify({'error': 'Invalid or expired file ID'}), 400
    
    if not columns_to_anonymize:
        return jsonify({'error': 'No columns selected for anonymization'}), 400
    
    if not secret_key:
        return jsonify({'error': 'No secret key provided'}), 400
    
    try:
        file_info = file_storage[file_id]
        
        # Read with same parameters as initial upload
        df = pd.read_csv(
            file_info['filepath'],
            encoding=file_info.get('encoding', 'utf-8'),
            sep=file_info.get('delimiter', ','),
            on_bad_lines='warn',
            encoding_errors='replace',
            dtype=str
        )
        
        # Strip BOM from column names if present
        df.columns = [col.lstrip('\ufeff').strip() for col in df.columns]
        
        # Anonymize selected columns
        for col in columns_to_anonymize:
            if col in df.columns:
                df[col] = df[col].apply(lambda x: anonymize_value(x, secret_key))
        
        # Save anonymized file - use original name with -anonymized suffix
        original_name = file_info['original_filename']
        # Remove .csv extension if present and add -anonymized.csv
        if original_name.lower().endswith('.csv'):
            base_name = original_name[:-4]
        else:
            base_name = original_name
        anonymized_filename = f"{base_name}-anonymized.csv"
        anonymized_filepath = os.path.join(
            app.config['UPLOAD_FOLDER'],
            f"{file_id}_{anonymized_filename}"
        )
        
        # Save with UTF-8 encoding and comma delimiter for consistency
        df.to_csv(anonymized_filepath, index=False, encoding='utf-8')
        
        # Update storage with anonymized file info
        file_storage[file_id]['anonymized_filepath'] = anonymized_filepath
        file_storage[file_id]['anonymized_filename'] = anonymized_filename
        
        return jsonify({
            'success': True,
            'message': f'Successfully anonymized {len(columns_to_anonymize)} column(s)',
            'anonymized_columns': columns_to_anonymize
        })
    
    except Exception as e:
        return jsonify({'error': f'Error during anonymization: {str(e)}'}), 500


@app.route('/download/<file_id>')
def download(file_id):
    """Download the anonymized CSV file."""
    if file_id not in file_storage:
        return jsonify({'error': 'Invalid or expired file ID'}), 400
    
    file_info = file_storage[file_id]
    
    if 'anonymized_filepath' not in file_info:
        return jsonify({'error': 'File has not been anonymized yet'}), 400
    
    return send_file(
        file_info['anonymized_filepath'],
        as_attachment=True,
        download_name=file_info['anonymized_filename'],
        mimetype='text/csv'
    )


@app.route('/cleanup/<file_id>', methods=['POST'])
def cleanup(file_id):
    """Clean up uploaded files after download."""
    if file_id in file_storage:
        file_info = file_storage[file_id]
        
        # Remove original file
        if os.path.exists(file_info.get('filepath', '')):
            os.remove(file_info['filepath'])
        
        # Remove anonymized file
        if os.path.exists(file_info.get('anonymized_filepath', '')):
            os.remove(file_info['anonymized_filepath'])
        
        del file_storage[file_id]
    
    return jsonify({'success': True})


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
