# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

__all__ = ['MetadataResolver', 'create_resolver']

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import asymmetric, serialization

from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2459

from u2flib_server.jsapi import MetadataObject
from u2flib_server.attestation.data import YUBICO
import os
import json


class MetadataResolver(object):

    def __init__(self):
        self._identifiers = {}  # identifier -> Metadata
        self._certs = {}  # Subject -> Cert
        self._metadata = {}  # Cert -> Metadata

    def add_metadata(self, metadata):
        metadata = MetadataObject.wrap(metadata)

        if metadata.identifier in self._identifiers:
            existing = self._identifiers[metadata.identifier]
            if metadata.version <= existing.version:
                return  # Older version
            else:
                # Re-index everything
                self._identifiers[metadata.identifier] = metadata
                self._certs.clear()
                self._metadata.clear()
                for metadata in self._identifiers.values():
                    self._index(metadata)
        else:
            self._identifiers[metadata.identifier] = metadata
            self._index(metadata)

    @staticmethod
    def _name_key(name):
        """Returns a dictionary key based on a certificate name attribute."""
        # TODO There must be a better way
        return tuple((attr.oid.dotted_string, attr.value) for attr in name)

    def _index(self, metadata):
        for cert_pem in metadata.trustedCertificates:
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            subject = self._name_key(cert.subject)
            if subject not in self._certs:
                self._certs[subject] = []
            self._certs[subject].append(cert)
            self._metadata[cert] = metadata

    @staticmethod
    def _bitstring_bytes(bitstring):
        """Returns the raw bytes in a pyasn1 BitString
        """
        bits = ''.join(str(bit) for bit in bitstring)
        byte_size_bits = [bits[n:n+8] for n in range(0, len(bits), 8)]
        return bytes(bytearray(int(chunk, 2) for chunk in byte_size_bits))

    @staticmethod
    def _verifier(pubkey, sig, sig_hash_algorithm):
        """Returns a suitable cryptography AsymmetricVerificationContext
        instance
        """
        if isinstance(pubkey, asymmetric.ec.EllipticCurvePublicKey):
            ec_sig_algorithm = asymmetric.ec.EllipticCurveSignatureAlgorithm(
                sig_hash_algorithm,
            )
            return pubkey.verifier(sig, ec_sig_algorithm)

        elif isinstance(pubkey, asymmetric.dsa.DSAPublicKey):
            backend = default_backend()
            return pubkey.verifier(sig, sig_hash_algorithm, backend)

        elif isinstance(pubkey, asymmetric.rsa.RSAPublicKey):
            padding = asymmetric.padding.PKCS1v15()
            return pubkey.verifier(sig, padding, sig_hash_algorithm)

    def _verify(self, cert, issuer_cert):
        """Returns True if cert contains a correct signature made using the
        private key for issuer_cert

        NB: This *only* checks the signature. No other checks are performed,
        e.g. the trust chain of the issuer_cert is not checked,
        neither certificate is checked for expiry, etc.
        """
        # Serialize from cryptography.x509 objects
        cert_der = cert.public_bytes(serialization.Encoding.DER)

        # Deserialize as pyasn1_modules.rfc2459.Certificate
        cert_asn, _ = decoder.decode(cert_der, asn1Spec=rfc2459.Certificate())

        issuer_pubkey = issuer_cert.public_key()
        cert_sig_bytes = self._bitstring_bytes(cert_asn['signatureValue'])
        verifier = self._verifier(
            issuer_pubkey,
            cert_sig_bytes,
            cert.signature_hash_algorithm,
        )
        verifier.update(encoder.encode(cert_asn['tbsCertificate']))
        try:
            verifier.verify()
        except InvalidSignature:
            return False
        return True

    def resolve(self, cert):
        for issuer in self._certs.get(self._name_key(cert.issuer), []):
            if self._verify(cert, issuer):
                return self._metadata[issuer]
        return None


def _load_from_file(fname):
    with open(fname, 'r') as f:
        return json.load(f)


def _load_from_dir(dname):
    return map(_load_from_file,
               [os.path.join(dname, d) for d in os.listdir(dname)
                if d.endswith('.json')])


def _add_data(resolver, data):
    if isinstance(data, list):
        for d in data:
            _add_data(resolver, d)
        return
    elif isinstance(data, basestring):
        if os.path.isdir(data):
            data = _load_from_dir(data)
        elif os.path.isfile(data):
            data = _load_from_file(data)
        return _add_data(resolver, data)
    if data is not None:
        resolver.add_metadata(data)


def create_resolver(data=None):
    resolver = MetadataResolver()
    if data is None:
        data = YUBICO
    _add_data(resolver, data)
    return resolver
