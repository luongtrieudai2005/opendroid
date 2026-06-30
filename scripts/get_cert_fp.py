"""Extract APK signing certificate fingerprint for Firebase App Check"""
import zipfile, hashlib, sys

APK = r"D:\temp\whatnot_data\base.apk"

with zipfile.ZipFile(APK, 'r') as z:
    cert_files = [n for n in z.namelist() if n.startswith('META-INF/') and any(n.endswith(ext) for ext in ('.RSA', '.DSA', '.EC', '.SF', '.MF'))]
    print(f"Cert files: {cert_files}")
    for c in cert_files:
        if c.endswith('.SF') or c.endswith('.MF'):
            continue
        data = z.read(c)
        # Try to find the certificate blob - RSA/DSA/EC signature files
        # The signature file is a PKCS7 signed data which contains the cert
        print(f"\n--- {c} (size={len(data)}) ---")
        print(f"First 100 bytes (hex): {data[:100].hex()}")
        
        # Search for "BEGIN CERTIFICATE" in text
        try:
            text = data.decode('utf-8', errors='replace')
            if 'CERTIFICATE' in text:
                print("Found PEM certificate!")
                import re
                pem = re.search(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', text, re.DOTALL)
                if pem:
                    cert_der = pem.group(1).strip()
                    print(f"PEM len: {len(cert_der)}")
        except:
            pass

# Try extracting from actual signature block (RSA file)
# The .RSA file is a DER-encoded PKCS7 SignedData
# We need to extract the certificate from it
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    
    for c in cert_files:
        if c.endswith('.RSA') or c.endswith('.DSA') or c.endswith('.EC'):
            data = z.read(c)
            # Try to load as PKCS7 signed data and extract cert
            from cryptography.hazmat.primitives.asymmetric import padding
            # PKCS7 in DER format - we can parse it manually
            # The cert is typically embedded in the signature block
            # Actually, let's just use keytool/jarsigner approach
            print(f"\n{c}: Cannot parse directly, trying openssl...")
except ImportError:
    print("cryptography not available")
