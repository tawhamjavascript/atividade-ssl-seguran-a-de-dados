from datetime import datetime
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from requests import request



def is_certificate_revoked(hostname: str) -> bool:
    """Check if a certificate is revoked by querying the Certificate Revocation List (CRL) of the CA.

    Args:
        hostname (str): Hostname of the domain to check.

    Returns:
        bool: True if the certificate is revoked, False otherwise.
    """
    try:
        # Get the certificate of the domain
        cert = ssl.get_server_certificate((hostname, 443))
        x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())

        # Get the CRL Distribution Points (CDP) from the certificate
        cdp = x509_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS).value

        # Get the URL of the CRL
        crl_url = cdp[0].full_name[0].value

        # Get the CRL
        crl = request("GET", crl_url).content

        # Get the serial number of the certificate
        serial_number = x509_cert.serial_number

        # Check if the certificate is revoked
        revoked = x509.load_der_x509_crl(crl, default_backend()).get_revoked_certificate_by_serial_number(serial_number)

        if revoked:
            print(f"The certificate of {hostname} is revoked.")
            return True
        else:
            print(f"The certificate of {hostname} is not revoked.")
            return False

    except socket.gaierror:
        print("Error: Invalid domain. Please enter a valid domain.")
        return False

    except Exception as e:
        print(f"Error: {e}")
        return False
    

def is_certificate_self_signed(hostname: str) -> bool:
    """Check if a certificate is self-signed.

    Args:
        hostname (str): Hostname of the domain to check.

    Returns:
        bool: True if the certificate is self-signed, False otherwise.
    """
    try:
        # Get the certificate of the domain
        cert = ssl.get_server_certificate((hostname, 443))
        x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())

        # Get the issuer of the certificate
        issuer = x509_cert.issuer

        # Get the subject of the certificate
        subject = x509_cert.subject

        # Check if the issuer and subject are the same
        if issuer == subject:
            print(f"The certificate of {hostname} is self-signed.")
            return True
        else:
            print(f"The certificate of {hostname} is not self-signed.")
            return False

    except socket.gaierror:
        print("Error: Invalid domain. Please enter a valid domain.")
        return False

    except Exception as e:
        print(f"Error: {e}")
        return False
    
def is_certificate_expired(hostname: str) -> bool:
    """Check if a certificate is expired.

    Args:
        hostname (str): Hostname of the domain to check.

    Returns:
        bool: True if the certificate is expired, False otherwise.
    """
    try:
        # Get the certificate of the domain
        cert = ssl.get_server_certificate((hostname, 443))
        x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())

        # Get the expiration date of the certificate
        expiration_date = x509_cert.not_valid_after

        # Check if the certificate is expired
        if expiration_date < datetime.now():
            print(f"The certificate of {hostname} is expired.")
            return True
        else:
            print(f"The certificate of {hostname} is not expired.")
            return False

    except socket.gaierror:
        print("Error: Invalid domain. Please enter a valid domain.")
        return False

    except Exception as e:
        print(f"Error: {e}")
        return False
    

def get_tls_ssl_versions(hostname: str) -> list:
    """Get the TLS/SSL versions supported by the domain.

    Args:
        hostname (str): Hostname of the domain to check.

    Returns:
        list: List of TLS/SSL versions supported by the domain.
    """
    try:
        # Get the TLS/SSL versions supported by the domain
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_ssl_versions = ssock.version()

        print(f"The TLS/SSL versions supported by {hostname} are: {tls_ssl_versions}")
        return tls_ssl_versions

    except socket.gaierror:
        print("Error: Invalid domain. Please enter a valid domain.")
        return False

    except Exception as e:
        print(f"Error: {e}")
        return False
    

def get_certificate_algorithm(hostname: str) -> str:
    """Get the algorithm used to sign the certificate of the domain.

    Args:
        hostname (str): Hostname of the domain to check.

    Returns:
        str: Algorithm used to sign the certificate of the domain.
    """
    try:
        # Get the certificate of the domain
        cert = ssl.get_server_certificate((hostname, 443))
        x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())

        # Get the algorithm used to sign the certificate
        algorithm = x509_cert.signature_hash_algorithm.name
        algorithm2 = x509_cert.signature_algorithm_oid._name

        print(f"The algorithm used to sign the certificate of {hostname} is: {algorithm} ({algorithm2})")
        return algorithm

    except socket.gaierror:
        print("Error: Invalid domain. Please enter a valid domain.")
        return False

    except Exception as e:
        print(f"Error: {e}")
        return False
    
    

while True:
    try:
        domain = input("Enter hostname: ")
        if not domain:
            print("Error: Domain cannot be empty. Please enter a valid domain.")
            continue
        
        is_certificate_revoked(domain)
        is_certificate_self_signed(domain)
        is_certificate_expired(domain)
        get_tls_ssl_versions(domain)
        get_certificate_algorithm(domain)

    except ValueError:
        print("Invalid input. Please try again.")