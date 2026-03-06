"""
Unit tests for format_validators.py

This Project Is Made By Kanishk Soni
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from src.python.core_analyzer import FormatValidation
from src.python.format_validators import (
    BaseValidator,
    ImageValidator,
    PDFValidator,
    ArchiveValidator,
    DocumentValidator,
    MediaValidator,
    ValidatorFactory
)


class TestBaseValidator:
    """Test cases for BaseValidator abstract class."""
    
    def test_base_validator_is_abstract(self):
        """Test that BaseValidator cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseValidator()
    
    def test_base_validator_methods_raise_not_implemented(self):
        """Test that abstract methods raise NotImplementedError."""
        
        class ConcreteValidator(BaseValidator):
            pass
        
        validator = ConcreteValidator()
        
        with pytest.raises(NotImplementedError):
            validator.validate("/test/file")
        
        with pytest.raises(NotImplementedError):
            validator.get_supported_extensions()


class TestImageValidator:
    """Test cases for ImageValidator class."""
    
    def test_image_validator_initialization(self):
        """Test ImageValidator initialization."""
        validator = ImageValidator()
        assert isinstance(validator, BaseValidator)
    
    def test_get_supported_extensions(self):
        """Test getting supported image extensions."""
        validator = ImageValidator()
        extensions = validator.get_supported_extensions()
        
        assert isinstance(extensions, (list, tuple, set))
        assert '.jpg' in extensions or '.jpeg' in extensions
        assert '.png' in extensions
        assert '.gif' in extensions
        assert '.bmp' in extensions
        assert '.tiff' in extensions or '.tif' in extensions
    
    @patch('src.python.format_validators.Image')
    def test_validate_valid_jpeg(self, mock_image_class, temp_file):
        """Test validating a valid JPEG image."""
        # Mock successful image opening
        mock_image = Mock()
        mock_image.verify.return_value = None
        mock_image_class.open.return_value.__enter__.return_value = mock_image
        
        validator = ImageValidator()
        test_file = temp_file("test.jpg", b"fake jpeg content", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert isinstance(result, FormatValidation)
        assert result.is_valid is True
        assert result.error_message is None
        assert result.format_info is not None
    
    @patch('src.python.format_validators.Image')
    def test_validate_corrupted_jpeg(self, mock_image_class, temp_file):
        """Test validating a corrupted JPEG image."""
        # Mock image verification failure
        mock_image_class.open.side_effect = Exception("Corrupt JPEG data")
        
        validator = ImageValidator()
        test_file = temp_file("corrupt.jpg", b"corrupted jpeg content", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert isinstance(result, FormatValidation)
        assert result.is_valid is False
        assert "Corrupt JPEG data" in result.error_message
    
    @patch('src.python.format_validators.Image')
    def test_validate_unsupported_image_format(self, mock_image_class, temp_file):
        """Test validating an unsupported image format."""
        mock_image_class.open.side_effect = Exception("cannot identify image file")
        
        validator = ImageValidator()
        test_file = temp_file("unknown.xyz", b"not an image", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert result.is_valid is False
        assert "cannot identify image file" in result.error_message.lower()
    
    def test_validate_nonexistent_file(self):
        """Test validating non-existent image file."""
        validator = ImageValidator()
        
        result = validator.validate("/nonexistent/image.jpg")
        
        assert result.is_valid is False
        assert result.error_message is not None
    
    @patch('src.python.format_validators.Image')
    def test_validate_image_with_metadata(self, mock_image_class, temp_file):
        """Test validating image and extracting metadata."""
        mock_image = Mock()
        mock_image.verify.return_value = None
        mock_image.format = "JPEG"
        mock_image.size = (1920, 1080)
        mock_image.mode = "RGB"
        mock_image_class.open.return_value.__enter__.return_value = mock_image
        
        validator = ImageValidator()
        test_file = temp_file("metadata.jpg", b"jpeg with metadata", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert result.is_valid is True
        assert result.format_info is not None
        assert result.format_info.get('format') == "JPEG"
        assert result.format_info.get('size') == (1920, 1080)
        assert result.format_info.get('mode') == "RGB"


class TestPDFValidator:
    """Test cases for PDFValidator class."""
    
    def test_pdf_validator_initialization(self):
        """Test PDFValidator initialization."""
        validator = PDFValidator()
        assert isinstance(validator, BaseValidator)
    
    def test_get_supported_extensions(self):
        """Test getting supported PDF extensions."""
        validator = PDFValidator()
        extensions = validator.get_supported_extensions()
        
        assert isinstance(extensions, (list, tuple, set))
        assert '.pdf' in extensions
    
    @patch('src.python.format_validators.PdfReader')
    def test_validate_valid_pdf(self, mock_pdf_reader, temp_file):
        """Test validating a valid PDF file."""
        # Mock successful PDF reading
        mock_reader = Mock()
        mock_reader.is_encrypted = False
        mock_reader.pages = [Mock(), Mock()]  # At least one page
        mock_pdf_reader.return_value = mock_reader
        
        validator = PDFValidator()
        test_file = temp_file("valid.pdf", b"%PDF-1.4\nvalid pdf content", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert isinstance(result, FormatValidation)
        assert result.is_valid is True
        assert result.error_message is None
        assert result.format_info is not None
    
    @patch('src.python.format_validators.PdfReader')
    def test_validate_corrupted_pdf(self, mock_pdf_reader, temp_file):
        """Test validating a corrupted PDF file."""
        mock_pdf_reader.side_effect = Exception("PDF header not found")
        
        validator = PDFValidator()
        test_file = temp_file("corrupt.pdf", b"not a pdf file", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert result.is_valid is False
        assert "PDF header not found" in result.error_message
    
    @patch('src.python.format_validators.PdfReader')
    def test_validate_encrypted_pdf(self, mock_pdf_reader, temp_file):
        """Test validating an encrypted PDF file."""
        mock_reader = Mock()
        mock_reader.is_encrypted = True
        mock_reader.decrypt.side_effect = Exception("Password required")
        mock_pdf_reader.return_value = mock_reader
        
        validator = PDFValidator()
        test_file = temp_file("encrypted.pdf", b"%PDF-1.4\nencrypted content", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert result.is_valid is False
        assert "encrypted" in result.error_message.lower() or "password" in result.error_message.lower()
    
    @patch('src.python.format_validators.PdfReader')
    def test_validate_pdf_with_metadata(self, mock_pdf_reader, temp_file):
        """Test validating PDF and extracting metadata."""
        mock_reader = Mock()
        mock_reader.is_encrypted = False
        mock_reader.pages = [Mock(), Mock()]
        mock_reader.metadata = {
            '/Title': 'Test Document',
            '/Author': 'Test Author',
            '/Creator': 'Test Creator'
        }
        mock_reader.getNumPages.return_value = 2
        mock_pdf_reader.return_value = mock_reader
        
        validator = PDFValidator()
        test_file = temp_file("metadata.pdf", b"%PDF-1.4\npdf with metadata", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert result.is_valid is True
        assert result.format_info is not None
        assert result.format_info.get('pages') == 2
        assert result.format_info.get('title') == 'Test Document'
        assert result.format_info.get('author') == 'Test Author'


class TestArchiveValidator:
    """Test cases for ArchiveValidator class."""
    
    def test_archive_validator_initialization(self):
        """Test ArchiveValidator initialization."""
        validator = ArchiveValidator()
        assert isinstance(validator, BaseValidator)
    
    def test_get_supported_extensions(self):
        """Test getting supported archive extensions."""
        validator = ArchiveValidator()
        extensions = validator.get_supported_extensions()
        
        assert isinstance(extensions, (list, tuple, set))
        assert '.zip' in extensions
    
    @patch('src.python.format_validators.ZipFile')
    def test_validate_valid_zip(self, mock_zipfile, temp_file):
        """Test validating a valid ZIP file."""
        # Mock successful ZIP file opening
        mock_zip = Mock()
        mock_zip.testzip.return_value = None  # No bad files
        mock_zip.infolist.return_value = [Mock(filename='test.txt')]
        mock_zipfile.return_value.__enter__.return_value = mock_zip
        
        validator = ArchiveValidator()
        test_file = temp_file("valid.zip", b"PK\x03\x04valid zip content", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert isinstance(result, FormatValidation)
        assert result.is_valid is True
        assert result.error_message is None
        assert result.format_info is not None
    
    @patch('src.python.format_validators.ZipFile')
    def test_validate_corrupted_zip(self, mock_zipfile, temp_file):
        """Test validating a corrupted ZIP file."""
        mock_zipfile.side_effect = Exception("Bad magic number for file header")
        
        validator = ArchiveValidator()
        test_file = temp_file("corrupt.zip", b"not a zip file", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert result.is_valid is False
        assert "Bad magic number" in result.error_message
    
    @patch('src.python.format_validators.ZipFile')
    def test_validate_zip_with_bad_files(self, mock_zipfile, temp_file):
        """Test validating ZIP file with corrupted internal files."""
        mock_zip = Mock()
        mock_zip.testzip.return_value = "bad_file.txt"  # Bad file found
        mock_zip.infolist.return_value = [Mock(filename='bad_file.txt')]
        mock_zipfile.return_value.__enter__.return_value = mock_zip
        
        validator = ArchiveValidator()
        test_file = temp_file("bad.zip", b"PK\x03\x04zip with bad files", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert result.is_valid is False
        assert "bad_file.txt" in result.error_message
    
    @patch('src.python.format_validators.ZipFile')
    def test_validate_zip_with_metadata(self, mock_zipfile, temp_file):
        """Test validating ZIP and extracting metadata."""
        mock_file_info = Mock()
        mock_file_info.filename = "test.txt"
        mock_file_info.file_size = 1024
        mock_file_info.compress_size = 512
        mock_file_info.date_time = (2024, 1, 15, 10, 30, 0)
        
        mock_zip = Mock()
        mock_zip.testzip.return_value = None
        mock_zip.infolist.return_value = [mock_file_info]
        mock_zipfile.return_value.__enter__.return_value = mock_zip
        
        validator = ArchiveValidator()
        test_file = temp_file("metadata.zip", b"PK\x03\x04zip with metadata", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert result.is_valid is True
        assert result.format_info is not None
        assert result.format_info.get('file_count') == 1
        assert result.format_info.get('total_size') == 1024
        assert result.format_info.get('compressed_size') == 512


class TestDocumentValidator:
    """Test cases for DocumentValidator class."""
    
    def test_document_validator_initialization(self):
        """Test DocumentValidator initialization."""
        validator = DocumentValidator()
        assert isinstance(validator, BaseValidator)
    
    def test_get_supported_extensions(self):
        """Test getting supported document extensions."""
        validator = DocumentValidator()
        extensions = validator.get_supported_extensions()
        
        assert isinstance(extensions, (list, tuple, set))
        assert '.docx' in extensions or '.doc' in extensions
        assert '.xlsx' in extensions or '.xls' in extensions
        assert '.txt' in extensions
    
    @patch('src.python.format_validators.docx.Document')
    def test_validate_valid_docx(self, mock_docx_document, temp_file):
        """Test validating a valid DOCX file."""
        mock_doc = Mock()
        mock_doc.core_properties.title = "Test Document"
        mock_doc.paragraphs = [Mock(text="Test paragraph")]
        mock_docx_document.return_value = mock_doc
        
        validator = DocumentValidator()
        test_file = temp_file("valid.docx", b"fake docx content", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert isinstance(result, FormatValidation)
        assert result.is_valid is True
        assert result.error_message is None
    
    @patch('src.python.format_validators.docx.Document')
    def test_validate_corrupted_docx(self, mock_docx_document, temp_file):
        """Test validating a corrupted DOCX file."""
        mock_docx_document.side_effect = Exception("Package not found")
        
        validator = DocumentValidator()
        test_file = temp_file("corrupt.docx", b"not a docx file", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert result.is_valid is False
        assert "Package not found" in result.error_message
    
    def test_validate_text_file(self, temp_file):
        """Test validating a plain text file."""
        validator = DocumentValidator()
        test_file = temp_file("document.txt", "This is a valid text document.")
        
        result = validator.validate(str(test_file))
        
        # Text files should generally be considered valid if they can be read
        assert isinstance(result, FormatValidation)
        # Text validation might be very permissive
        assert result.error_message is None or "valid" in result.error_message.lower()
    
    def test_validate_empty_text_file(self, temp_file):
        """Test validating an empty text file."""
        validator = DocumentValidator()
        test_file = temp_file("empty.txt", "")
        
        result = validator.validate(str(test_file))
        
        assert isinstance(result, FormatValidation)
        # Empty files might be considered valid or invalid depending on implementation


class TestMediaValidator:
    """Test cases for MediaValidator class."""
    
    def test_media_validator_initialization(self):
        """Test MediaValidator initialization."""
        validator = MediaValidator()
        assert isinstance(validator, BaseValidator)
    
    def test_get_supported_extensions(self):
        """Test getting supported media extensions."""
        validator = MediaValidator()
        extensions = validator.get_supported_extensions()
        
        assert isinstance(extensions, (list, tuple, set))
        # Should include common media formats
        media_extensions = ['.mp4', '.avi', '.mov', '.mp3', '.wav', '.flac']
        assert any(ext in extensions for ext in media_extensions)
    
    @patch('src.python.format_validators.ffmpeg.probe')
    def test_validate_valid_media(self, mock_ffmpeg_probe, temp_file):
        """Test validating a valid media file."""
        # Mock successful media probe
        mock_probe_data = {
            'streams': [{'codec_type': 'video', 'codec_name': 'h264'}],
            'format': {'format_name': 'mov,mp4,m4a,3gp,3g2,mj2'}
        }
        mock_ffmpeg_probe.return_value = mock_probe_data
        
        validator = MediaValidator()
        test_file = temp_file("valid.mp4", b"fake mp4 content", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert isinstance(result, FormatValidation)
        assert result.is_valid is True
        assert result.error_message is None
        assert result.format_info is not None
    
    @patch('src.python.format_validators.ffmpeg.probe')
    def test_validate_corrupted_media(self, mock_ffmpeg_probe, temp_file):
        """Test validating a corrupted media file."""
        mock_ffmpeg_probe.side_effect = Exception("Invalid data found when processing input")
        
        validator = MediaValidator()
        test_file = temp_file("corrupt.mp4", b"not a media file", binary=True)
        
        result = validator.validate(str(test_file))
        
        assert result.is_valid is False
        assert "Invalid data found" in result.error_message
    
    @patch('src.python.format_validators.ffmpeg')
    def test_validate_media_ffmpeg_unavailable(self, mock_ffmpeg, temp_file):
        """Test validation when FFmpeg is not available."""
        mock_ffmpeg.probe.side_effect = ImportError("No module named 'ffmpeg'")
        
        validator = MediaValidator()
        test_file = temp_file("test.mp4", b"fake media", binary=True)
        
        result = validator.validate(str(test_file))
        
        # Should handle missing FFmpeg gracefully
        assert isinstance(result, FormatValidation)
        # May be marked as valid with limited validation or unavailable
        assert result.error_message is None or "unavailable" in result.error_message.lower()


class TestValidatorFactory:
    """Test cases for ValidatorFactory class."""
    
    def test_get_validator_for_image(self):
        """Test getting validator for image files."""
        validator = ValidatorFactory.get_validator("image.jpg")
        assert isinstance(validator, ImageValidator)
        
        validator = ValidatorFactory.get_validator("photo.png")
        assert isinstance(validator, ImageValidator)
    
    def test_get_validator_for_pdf(self):
        """Test getting validator for PDF files."""
        validator = ValidatorFactory.get_validator("document.pdf")
        assert isinstance(validator, PDFValidator)
    
    def test_get_validator_for_archive(self):
        """Test getting validator for archive files."""
        validator = ValidatorFactory.get_validator("archive.zip")
        assert isinstance(validator, ArchiveValidator)
    
    def test_get_validator_for_document(self):
        """Test getting validator for document files."""
        validator = ValidatorFactory.get_validator("report.docx")
        assert isinstance(validator, DocumentValidator)
        
        validator = ValidatorFactory.get_validator("data.xlsx")
        assert isinstance(validator, DocumentValidator)
    
    def test_get_validator_for_media(self):
        """Test getting validator for media files."""
        validator = ValidatorFactory.get_validator("video.mp4")
        assert isinstance(validator, MediaValidator)
        
        validator = ValidatorFactory.get_validator("audio.mp3")
        assert isinstance(validator, MediaValidator)
    
    def test_get_validator_for_unknown_type(self):
        """Test getting validator for unknown file type."""
        validator = ValidatorFactory.get_validator("unknown.xyz")
        # Should return None or a default validator
        assert validator is None or isinstance(validator, BaseValidator)
    
    def test_get_validator_case_insensitive(self):
        """Test that validator selection is case insensitive."""
        validator_lower = ValidatorFactory.get_validator("image.JPG")
        validator_upper = ValidatorFactory.get_validator("image.jpg")
        
        assert type(validator_lower) == type(validator_upper)
    
    def test_get_validator_with_path(self):
        """Test getting validator with full file path."""
        validator = ValidatorFactory.get_validator("/path/to/document.pdf")
        assert isinstance(validator, PDFValidator)
        
        validator = ValidatorFactory.get_validator("C:\\path\\to\\image.png")
        assert isinstance(validator, ImageValidator)
    
    def test_register_custom_validator(self):
        """Test registering a custom validator."""
        class CustomValidator(BaseValidator):
            def validate(self, file_path):
                return FormatValidation(is_valid=True)
            
            def get_supported_extensions(self):
                return ['.custom']
        
        # Register custom validator
        ValidatorFactory.register_validator('.custom', CustomValidator)
        
        # Test that it's used
        validator = ValidatorFactory.get_validator("test.custom")
        assert isinstance(validator, CustomValidator)
    
    def test_get_all_supported_extensions(self):
        """Test getting all supported extensions."""
        extensions = ValidatorFactory.get_all_supported_extensions()
        
        assert isinstance(extensions, set)
        assert len(extensions) > 0
        
        # Should include common extensions
        common_extensions = {'.jpg', '.jpeg', '.png', '.pdf', '.zip', '.docx', '.txt'}
        assert extensions.intersection(common_extensions)
