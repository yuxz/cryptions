const { X509Certificate } = require('crypto');

const certPem = "-----BEGIN CERTIFICATE-----\nMIIB7zCCAaGgAwIBAgIUNz0KNTThCckXwOohEC6QcXZVxykwBQYDK2VwMHQxCzAJ\nBgNVBAYTAkpQMQ4wDAYDVQQIEwVUb2t5bzESMBAGA1UEBxMJTWluYXRvLWt1MRMw\nEQYDVQQKEwpKYXNteSBJbmMuMRAwDgYDVQQLEwdSb290IENBMRowGAYDVQQDExFK\nQVNNWSBJTkMgUm9vdCBDQTAeFw0yMTEwMTQwNDM5MDBaFw0yMjExMjExMTQzMDBa\nMCoxDzANBgNVBAsTBmNsaWVudDEXMBUGA1UEAxMOamFzbXktY2EtYWRtaW4wWTAT\nBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT+oND5KeQxsQLMKiHxPK1trVmkt2ZcbmMl\nwtKOL3Oca8XZp4erVucb7j0QCloQVyBsJkDYwawGaqwnpDIzVbPEo2AwXjAOBgNV\nHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU98ImTLjH/1AJ5Ar4\nXEM5YKoG1vcwHwYDVR0jBBgwFoAU6tWhR2/3u2jz4RB2TFc8yZqFwnEwBQYDK2Vw\nA0EA7wVJyjjAommV6Sccr5DaahR20SPPmHFOA5aHK1rWGDrCajtsm+tHgF2OcKhm\nLlc31piyJz4sl/jRF202/AlABg==\n-----END CERTIFICATE-----\n";

// const x509 = new X509Certificate(Buffer.from(certPem, 'base64'));
const x509 = new X509Certificate(certPem);

console.log('x509.publicKey', x509.publicKey);
console.log('x509.publicKey.asymmetricKeyType', x509.publicKey.asymmetricKeyType)

