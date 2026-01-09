"""Unit tests for the CSV Anonymizer application."""
import os
import io
import csv
import tempfile
import pytest
from app import app, anonymize_value, file_storage, detect_delimiter, \
    detect_encoding, read_csv_robust


@pytest.fixture
def client():
    """Create a test client for the Flask application."""
    app.config['TESTING'] = True
    # Use a temporary directory for uploads during tests
    with tempfile.TemporaryDirectory() as tmpdir:
        app.config['UPLOAD_FOLDER'] = tmpdir
        with app.test_client() as client:
            yield client
        # Clear file storage after each test
        file_storage.clear()


@pytest.fixture
def sample_csv():
    """Create a sample CSV file content."""
    return b"name,email,age\nJohn Doe,john@example.com,30\nJane Smith,jane@example.com,25"


class TestAnonymizeValue:
    """Tests for the anonymize_value function."""

    def test_anonymize_regular_value(self):
        """Test that regular values are anonymized."""
        result = anonymize_value("test_value", "secret_key")
        assert result is not None
        assert result != "test_value"
        assert len(result) == 16  # HMAC truncated to 16 chars

    def test_anonymize_empty_string(self):
        """Test that empty strings remain empty."""
        result = anonymize_value("", "secret_key")
        assert result == ""

    def test_anonymize_none_value(self):
        """Test that None values remain None."""
        import pandas as pd
        result = anonymize_value(pd.NA, "secret_key")
        assert pd.isna(result)

    def test_consistent_anonymization(self):
        """Test that same value + key produces same hash."""
        result1 = anonymize_value("test", "key")
        result2 = anonymize_value("test", "key")
        assert result1 == result2

    def test_different_keys_produce_different_results(self):
        """Test that different keys produce different hashes."""
        result1 = anonymize_value("test", "key1")
        result2 = anonymize_value("test", "key2")
        assert result1 != result2


class TestIndexRoute:
    """Tests for the index route."""

    def test_index_returns_200(self, client):
        """Test that the index page loads successfully."""
        response = client.get('/')
        assert response.status_code == 200

    def test_index_returns_html(self, client):
        """Test that the index page returns HTML content."""
        response = client.get('/')
        assert b'<!DOCTYPE html>' in response.data or b'<html' in response.data


class TestUploadRoute:
    """Tests for the upload route."""

    def test_upload_no_file(self, client):
        """Test upload without a file returns error."""
        response = client.post('/upload')
        assert response.status_code == 400
        assert b'No file provided' in response.data

    def test_upload_empty_filename(self, client):
        """Test upload with empty filename returns error."""
        response = client.post('/upload', data={
            'file': (io.BytesIO(b''), '')
        })
        assert response.status_code == 400
        assert b'No file selected' in response.data

    def test_upload_non_csv_file(self, client):
        """Test upload of non-CSV file returns error."""
        response = client.post('/upload', data={
            'file': (io.BytesIO(b'not a csv'), 'test.txt')
        }, content_type='multipart/form-data')
        assert response.status_code == 400
        assert b'Only CSV files are allowed' in response.data

    def test_upload_valid_csv(self, client, sample_csv):
        """Test upload of valid CSV file."""
        response = client.post('/upload', data={
            'file': (io.BytesIO(sample_csv), 'test.csv')
        }, content_type='multipart/form-data')
        assert response.status_code == 200
        json_data = response.get_json()
        assert 'file_id' in json_data
        assert 'columns' in json_data
        assert json_data['columns'] == ['name', 'email', 'age']
        assert json_data['row_count'] == 2


class TestAnonymizeRoute:
    """Tests for the anonymize route."""

    def test_anonymize_no_data(self, client):
        """Test anonymize without data returns error."""
        response = client.post('/anonymize', json=None)
        # Flask returns 415 for missing content-type or 400 for invalid data
        assert response.status_code in [400, 415]

    def test_anonymize_invalid_file_id(self, client):
        """Test anonymize with invalid file ID returns error."""
        response = client.post('/anonymize', json={
            'file_id': 'invalid_id',
            'columns': ['name'],
            'secret_key': 'test_key'
        })
        assert response.status_code == 400
        assert b'Invalid or expired file ID' in response.data

    def test_anonymize_no_columns(self, client, sample_csv):
        """Test anonymize without columns returns error."""
        # First upload a file
        upload_response = client.post('/upload', data={
            'file': (io.BytesIO(sample_csv), 'test.csv')
        }, content_type='multipart/form-data')
        file_id = upload_response.get_json()['file_id']

        # Try to anonymize without columns
        response = client.post('/anonymize', json={
            'file_id': file_id,
            'columns': [],
            'secret_key': 'test_key'
        })
        assert response.status_code == 400
        assert b'No columns selected' in response.data

    def test_anonymize_no_secret_key(self, client, sample_csv):
        """Test anonymize without secret key returns error."""
        # First upload a file
        upload_response = client.post('/upload', data={
            'file': (io.BytesIO(sample_csv), 'test.csv')
        }, content_type='multipart/form-data')
        file_id = upload_response.get_json()['file_id']

        # Try to anonymize without secret key
        response = client.post('/anonymize', json={
            'file_id': file_id,
            'columns': ['name'],
            'secret_key': ''
        })
        assert response.status_code == 400
        assert b'No secret key provided' in response.data

    def test_anonymize_success(self, client, sample_csv):
        """Test successful anonymization."""
        # First upload a file
        upload_response = client.post('/upload', data={
            'file': (io.BytesIO(sample_csv), 'test.csv')
        }, content_type='multipart/form-data')
        file_id = upload_response.get_json()['file_id']

        # Anonymize
        response = client.post('/anonymize', json={
            'file_id': file_id,
            'columns': ['name', 'email'],
            'secret_key': 'test_key'
        })
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data['success'] is True
        assert 'name' in json_data['anonymized_columns']
        assert 'email' in json_data['anonymized_columns']


class TestDownloadRoute:
    """Tests for the download route."""

    def test_download_invalid_file_id(self, client):
        """Test download with invalid file ID returns error."""
        response = client.get('/download/invalid_id')
        assert response.status_code == 400

    def test_download_not_anonymized(self, client, sample_csv):
        """Test download before anonymization returns error."""
        # First upload a file
        upload_response = client.post('/upload', data={
            'file': (io.BytesIO(sample_csv), 'test.csv')
        }, content_type='multipart/form-data')
        file_id = upload_response.get_json()['file_id']

        # Try to download without anonymizing
        response = client.get(f'/download/{file_id}')
        assert response.status_code == 400
        assert b'not been anonymized' in response.data

    def test_download_success(self, client, sample_csv):
        """Test successful download of anonymized file."""
        # Upload
        upload_response = client.post('/upload', data={
            'file': (io.BytesIO(sample_csv), 'test.csv')
        }, content_type='multipart/form-data')
        file_id = upload_response.get_json()['file_id']

        # Anonymize
        client.post('/anonymize', json={
            'file_id': file_id,
            'columns': ['name'],
            'secret_key': 'test_key'
        })

        # Download
        response = client.get(f'/download/{file_id}')
        assert response.status_code == 200
        assert response.content_type == 'text/csv; charset=utf-8'

    def test_download_filename_format(self, client, sample_csv):
        """Test that downloaded file has correct filename format."""
        # Upload
        upload_response = client.post('/upload', data={
            'file': (io.BytesIO(sample_csv), 'mydata.csv')
        }, content_type='multipart/form-data')
        file_id = upload_response.get_json()['file_id']

        # Anonymize
        client.post('/anonymize', json={
            'file_id': file_id,
            'columns': ['name'],
            'secret_key': 'test_key'
        })

        # Download
        response = client.get(f'/download/{file_id}')
        assert response.status_code == 200
        # Check Content-Disposition header for filename
        content_disposition = response.headers.get('Content-Disposition', '')
        assert 'mydata-anonymized.csv' in content_disposition


class TestCleanupRoute:
    """Tests for the cleanup route."""

    def test_cleanup_removes_files(self, client, sample_csv):
        """Test that cleanup removes uploaded files."""
        # Upload
        upload_response = client.post('/upload', data={
            'file': (io.BytesIO(sample_csv), 'test.csv')
        }, content_type='multipart/form-data')
        file_id = upload_response.get_json()['file_id']

        # Anonymize
        client.post('/anonymize', json={
            'file_id': file_id,
            'columns': ['name'],
            'secret_key': 'test_key'
        })

        # Get file paths before cleanup
        original_path = file_storage[file_id]['filepath']
        anonymized_path = file_storage[file_id]['anonymized_filepath']

        # Cleanup
        response = client.post(f'/cleanup/{file_id}')
        assert response.status_code == 200
        assert response.get_json()['success'] is True

        # Verify files are deleted
        assert not os.path.exists(original_path)
        assert not os.path.exists(anonymized_path)
        assert file_id not in file_storage

    def test_cleanup_nonexistent_file(self, client):
        """Test cleanup of nonexistent file succeeds gracefully."""
        response = client.post('/cleanup/nonexistent_id')
        assert response.status_code == 200
        assert response.get_json()['success'] is True


class TestRobustCSVHandling:
    """Tests for robust CSV handling features."""

    def test_semicolon_delimiter(self, client):
        """Test that semicolon-delimited CSVs are handled."""
        csv_data = b"name;email;age\nJohn;john@test.com;30\nJane;jane@test.com;25"
        response = client.post('/upload', data={
            'file': (io.BytesIO(csv_data), 'semicolon.csv')
        }, content_type='multipart/form-data')
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data['columns'] == ['name', 'email', 'age']
        assert json_data['delimiter'] == 'semicolon'

    def test_tab_delimiter(self, client):
        """Test that tab-delimited CSVs are handled."""
        csv_data = b"name\temail\tage\nJohn\tjohn@test.com\t30"
        response = client.post('/upload', data={
            'file': (io.BytesIO(csv_data), 'tabs.csv')
        }, content_type='multipart/form-data')
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data['columns'] == ['name', 'email', 'age']
        assert json_data['delimiter'] == 'tab'

    def test_empty_file(self, client):
        """Test that empty files return an error."""
        response = client.post('/upload', data={
            'file': (io.BytesIO(b''), 'empty.csv')
        }, content_type='multipart/form-data')
        assert response.status_code == 400
        assert b'empty' in response.data.lower()

    def test_header_only_file(self, client):
        """Test that header-only files return an error."""
        csv_data = b"name,email,age\n"
        response = client.post('/upload', data={
            'file': (io.BytesIO(csv_data), 'header_only.csv')
        }, content_type='multipart/form-data')
        assert response.status_code == 400
        assert b'no data' in response.data.lower()

    def test_utf8_bom(self, client):
        """Test that UTF-8 BOM is stripped from column names."""
        # UTF-8 BOM + CSV content
        csv_data = b'\xef\xbb\xbfname,email,age\nJohn,john@test.com,30'
        response = client.post('/upload', data={
            'file': (io.BytesIO(csv_data), 'bom.csv')
        }, content_type='multipart/form-data')
        assert response.status_code == 200
        json_data = response.get_json()
        # BOM should be stripped from column name
        assert json_data['columns'][0] == 'name'

    def test_encoding_detection_returns_info(self, client):
        """Test that encoding info is returned."""
        csv_data = b"name,email\nJohn,john@test.com"
        response = client.post('/upload', data={
            'file': (io.BytesIO(csv_data), 'test.csv')
        }, content_type='multipart/form-data')
        assert response.status_code == 200
        json_data = response.get_json()
        assert 'encoding' in json_data

    def test_whitespace_only_values_not_anonymized(self):
        """Test that whitespace-only values are not anonymized."""
        result = anonymize_value("   ", "secret_key")
        assert result == "   "


class TestDelimiterDetection:
    """Tests for delimiter detection functionality."""

    def test_detect_comma_delimiter(self):
        """Test detection of comma delimiter."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv',
                                         delete=False) as f:
            f.write("name,email,age\nJohn,john@test.com,30")
            temp_path = f.name

        try:
            delimiter = detect_delimiter(temp_path, 'utf-8')
            assert delimiter == ','
        finally:
            os.unlink(temp_path)

    def test_detect_semicolon_delimiter(self):
        """Test detection of semicolon delimiter."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv',
                                         delete=False) as f:
            f.write("name;email;age\nJohn;john@test.com;30")
            temp_path = f.name

        try:
            delimiter = detect_delimiter(temp_path, 'utf-8')
            assert delimiter == ';'
        finally:
            os.unlink(temp_path)

    def test_detect_tab_delimiter(self):
        """Test detection of tab delimiter."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv',
                                         delete=False) as f:
            f.write("name\temail\tage\nJohn\tjohn@test.com\t30")
            temp_path = f.name

        try:
            delimiter = detect_delimiter(temp_path, 'utf-8')
            assert delimiter == '\t'
        finally:
            os.unlink(temp_path)

    def test_detect_quoted_fields_with_pipes(self):
        """Test that pipes in quoted fields don't confuse delimiter."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv',
                                         delete=False,
                                         encoding='utf-8') as f:
            f.write('"name","city","note"\n')
            f.write('"John","SF","||note||"\n')
            f.write('"Jane","LA","||text||"\n')
            temp_path = f.name

        try:
            delimiter = detect_delimiter(temp_path, 'utf-8')
            # Should detect comma, not pipe
            assert delimiter == ','
        finally:
            os.unlink(temp_path)

    def test_detect_quoted_fields_with_semicolons(self):
        """Test semicolon-delimited with quoted fields."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv',
                                         delete=False,
                                         encoding='utf-8') as f:
            f.write('"name";"email";"note"\n')
            f.write('"John";"john@test.com";"note;here"\n')
            temp_path = f.name

        try:
            delimiter = detect_delimiter(temp_path, 'utf-8')
            assert delimiter == ';'
        finally:
            os.unlink(temp_path)

    def test_delimiter_defaults_to_comma_on_error(self):
        """Test that comma is default when detection fails."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv',
                                         delete=False) as f:
            f.write("singlecolumn")
            temp_path = f.name

        try:
            delimiter = detect_delimiter(temp_path, 'utf-8')
            assert delimiter == ','
        finally:
            os.unlink(temp_path)


class TestEncodingDetection:
    """Tests for encoding detection functionality."""

    def test_detect_utf8_encoding(self):
        """Test detection of UTF-8 encoding."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv',
                                         delete=False,
                                         encoding='utf-8') as f:
            f.write("name,email\nJohn,john@test.com")
            temp_path = f.name

        try:
            encoding = detect_encoding(temp_path)
            assert encoding is not None
            assert isinstance(encoding, str)
        finally:
            os.unlink(temp_path)

    def test_detect_utf8_with_bom(self):
        """Test detection of UTF-8 with BOM."""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.csv',
                                         delete=False) as f:
            f.write(b'\xef\xbb\xbfname,email\nJohn,john@test.com')
            temp_path = f.name

        try:
            encoding = detect_encoding(temp_path)
            assert encoding is not None
        finally:
            os.unlink(temp_path)


class TestReadCSVRobust:
    """Tests for robust CSV reading functionality."""

    def test_read_simple_csv(self):
        """Test reading simple CSV file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv',
                                         delete=False,
                                         encoding='utf-8') as f:
            f.write("name,email,age\n")
            f.write("John,john@test.com,30\n")
            f.write("Jane,jane@test.com,25\n")
            temp_path = f.name

        try:
            df, encoding, delimiter = read_csv_robust(temp_path)
            assert len(df.columns) == 3
            assert df.columns.tolist() == ['name', 'email', 'age']
            assert len(df) == 2
            assert df.iloc[0]['name'] == 'John'
        finally:
            os.unlink(temp_path)

    def test_read_csv_with_bom(self):
        """Test reading CSV with UTF-8 BOM."""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.csv',
                                         delete=False) as f:
            f.write(b'\xef\xbb\xbfname,email,age\n')
            f.write(b'John,john@test.com,30\n')
            temp_path = f.name

        try:
            df, encoding, delimiter = read_csv_robust(temp_path)
            # BOM should be stripped from column names
            assert df.columns[0] == 'name'
            assert not df.columns[0].startswith('\ufeff')
        finally:
            os.unlink(temp_path)

    def test_read_quoted_csv(self):
        """Test reading CSV with quoted fields."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv',
                                         delete=False,
                                         encoding='utf-8') as f:
            f.write('"name","email","age"\n')
            f.write('"John Doe","john@test.com","30"\n')
            f.write('"Jane Smith","jane@test.com","25"\n')
            temp_path = f.name

        try:
            df, encoding, delimiter = read_csv_robust(temp_path)
            assert len(df.columns) == 3
            assert df.columns.tolist() == ['name', 'email', 'age']
            assert df.iloc[0]['name'] == 'John Doe'
        finally:
            os.unlink(temp_path)

    def test_read_quoted_csv_with_pipes_in_data(self):
        """Test reading quoted CSV where data contains pipes."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv',
                                         delete=False,
                                         encoding='utf-8') as f:
            f.write('"Guest_ID","City","Note"\n')
            f.write('"M001","SF","||City: SF||"\n')
            f.write('"M002","LA","||City: LA||"\n')
            temp_path = f.name

        try:
            df, encoding, delimiter = read_csv_robust(temp_path)
            assert len(df.columns) == 3
            assert df.columns.tolist() == ['Guest_ID', 'City', 'Note']
            # Verify pipes are in the data, not used as delimiter
            assert '||City: SF||' in df.iloc[0]['Note']
        finally:
            os.unlink(temp_path)

    def test_read_csv_semicolon_delimiter(self):
        """Test reading CSV with semicolon delimiter."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv',
                                         delete=False,
                                         encoding='utf-8') as f:
            f.write('name;email;age\n')
            f.write('John;john@test.com;30\n')
            temp_path = f.name

        try:
            df, encoding, delimiter = read_csv_robust(temp_path)
            assert delimiter == ';'
            assert len(df.columns) == 3
            assert df.columns.tolist() == ['name', 'email', 'age']
        finally:
            os.unlink(temp_path)

    def test_read_csv_with_spaces_after_delimiter(self):
        """Test that spaces after delimiters are handled."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv',
                                         delete=False,
                                         encoding='utf-8') as f:
            f.write('name, email, age\n')
            f.write('John, john@test.com, 30\n')
            temp_path = f.name

        try:
            df, encoding, delimiter = read_csv_robust(temp_path)
            # Columns should have spaces stripped
            assert df.columns[0].strip() == 'name'
            assert df.columns[1].strip() == 'email'
        finally:
            os.unlink(temp_path)


class TestUploadRouteWithQuotedCSV:
    """Tests for upload route with quoted CSV files."""

    def test_upload_quoted_csv(self, client):
        """Test upload of quoted CSV file."""
        csv_data = b'"name","email","age"\n' \
                   b'"John Doe","john@test.com","30"\n'
        response = client.post('/upload', data={
            'file': (io.BytesIO(csv_data), 'quoted.csv')
        }, content_type='multipart/form-data')
        assert response.status_code == 200
        json_data = response.get_json()
        assert json_data['columns'] == ['name', 'email', 'age']
        assert json_data['row_count'] == 1

    def test_upload_quoted_csv_with_pipes_in_data(self, client):
        """Test upload of quoted CSV with pipes in field values."""
        csv_data = b'"Guest_ID","City","Note"\n' \
                   b'"M001","SF","||City: SF||"\n' \
                   b'"M002","LA","||City: LA||"\n'
        response = client.post('/upload', data={
            'file': (io.BytesIO(csv_data), 'quoted_pipes.csv')
        }, content_type='multipart/form-data')
        assert response.status_code == 200
        json_data = response.get_json()
        # Should have 3 columns, not treating pipes as delimiter
        assert json_data['columns'] == ['Guest_ID', 'City', 'Note']
        assert json_data['row_count'] == 2

    def test_upload_utf8_bom_quoted_csv(self, client):
        """Test upload of UTF-8 BOM quoted CSV."""
        csv_data = b'\xef\xbb\xbf' \
                   b'"name","email","age"\n' \
                   b'"John","john@test.com","30"\n'
        response = client.post('/upload', data={
            'file': (io.BytesIO(csv_data), 'bom_quoted.csv')
        }, content_type='multipart/form-data')
        assert response.status_code == 200
        json_data = response.get_json()
        # BOM and quotes should be stripped
        assert json_data['columns'] == ['name', 'email', 'age']
        assert json_data['row_count'] == 1


