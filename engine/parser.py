import hmac
import hashlib
from lxml import etree
import copy

class L5XParser:
    """
    Enterprise-grade parser for PLC logic files (L5X / XML).
    Strips volatile fields (timestamps, sensor values) to prevent false positives
    and focuses only on structural logic elements.
    """
    def __init__(self, secret_key: bytes = b'OT_GUARD_SECRET_KEY'):
        self.secret_key = secret_key

    def normalize_xml(self, file_path: str) -> str:
        """
        Parses XML, removes volatile data, and returns a canonical string representation.
        """
        try:
            tree = etree.parse(file_path)
            root = tree.getroot()
            
            # Remove volatile attributes across all tags
            volatile_attributes = ['ExportDate', 'ExportOptions', 'Owner', 'SoftwareRevision']
            for elem in root.iter():
                for attr in volatile_attributes:
                    if attr in elem.attrib:
                        del elem.attrib[attr]
            
            # Find all <Data> tags inside <Tags> and remove volatile values like live counters
            # Specifically, values that are expected to change in real-time
            for data_elem in root.xpath('//Tag/Data'):
                # In real life, we would strip real-time values. 
                # For this implementation, we clear all inner text of Data tags to only check structure
                data_elem.text = ""
                
            # Canonicalize the XML to string
            canonical_xml = etree.tostring(root, method="c14n").decode('utf-8')
            return canonical_xml
            
        except etree.XMLSyntaxError as e:
            raise ValueError(f"Invalid XML file {file_path}: {e}")

    def sign_baseline(self, file_path: str) -> str:
        """
        Creates an HMAC-SHA256 signature of the normalized XML.
        """
        normalized_content = self.normalize_xml(file_path)
        signature = hmac.new(self.secret_key, normalized_content.encode('utf-8'), hashlib.sha256).hexdigest()
        return signature

    def check_drift(self, active_file: str, expected_signature: str) -> tuple[bool, str, str]:
        """
        Returns (has_drifted, current_content, current_signature)
        """
        current_content = self.normalize_xml(active_file)
        current_signature = self.sign_baseline(active_file)
        drifted = not hmac.compare_digest(current_signature, expected_signature)
        return drifted, current_content, current_signature
