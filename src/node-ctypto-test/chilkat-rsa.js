

const {
  generateKeyPairSync, 
	createSign,
  createVerify,
	sign,
	verify,
	createPublicKey,
	createPrivateKey,
	X509Certificate

} = require('crypto');


var os = require('os');
if (os.platform() == 'win32') {  
    if (os.arch() == 'ia32') {
        var chilkat = require('@chilkat/ck-node12-win-ia32');
    } else {
        var chilkat = require('@chilkat/ck-node12-win64'); 
    }
} else if (os.platform() == 'linux') {
    if (os.arch() == 'arm') {
        var chilkat = require('@chilkat/ck-node12-arm');
    } else if (os.arch() == 'x86') {
        var chilkat = require('@chilkat/ck-node12-linux32');
    } else {
        var chilkat = require('@chilkat/ck-node12-linux64');
    }
} else if (os.platform() == 'darwin') {
    var chilkat = require('@chilkat/ck-node12-macosx');
}




function chilkatExample() {

    // Note: Requires Chilkat v9.5.0.65 or greater.

    // This requires the Chilkat API to have been previously unlocked.
    // See Global Unlock Sample for sample code.

    // First generate an RSA private key.
    var rsa = new chilkat.Rsa();

    // Generate a random 2048-bit RSA key.
    var success = rsa.GenerateKey(2048);
    if (success !== true) {
        console.log(rsa.LastErrorText);
        return;
    }

    // Get the private key
    // privKey: PrivateKey
    var privKey = rsa.ExportPrivateKeyObj();

    // Create the CSR object and set properties.
    var csr = new chilkat.Csr();

    // Specify the Common Name.  This is the only required property.
    // For SSL/TLS certificates, this would be the domain name. 
    // For email certificates this would be the email address. 
    csr.CommonName = "mysubdomain.mydomain.com";

    // Country Name (2 letter code)
    csr.Country = "GB";

    // State or Province Name (full name)
    csr.State = "Yorks";

    // Locality Name (eg, city)
    csr.Locality = "York";

    // Organization Name (eg, company)
    csr.Company = "Internet Widgits Pty Ltd";

    // Organizational Unit Name (eg, secion/division)
    csr.CompanyDivision = "IT";

    // Email address
    csr.EmailAddress = "support@mydomain.com";

		const { publicKey, privateKey } = generateKeyPairSync('ed25519') 

    // Create the CSR using the private key.
    var pemStr = csr.GenCsrPem(privKey);
    if (csr.LastMethodSuccess !== true) {
        console.log(csr.LastErrorText);

        return;
    }

    // Save the private key and CSR to a files.
    // privKey.SavePkcs8EncryptedPemFile("password","qa_output/privKey1.pem");

    var fac = new chilkat.FileAccess();
    fac.WriteEntireTextFile("qa_output/csr1.pem",pemStr,"utf-8",false);

    // Show the CSR.
    console.log(pemStr);

    // Sample output:
    // The CSR PEM can be checked here:
    // https://www.networking4all.com/en/support/tools/csr+check/
    // Copy-and-paste the PEM into the online CSR Decoding / CSR Verification form

    // 	-----BEGIN CERTIFICATE REQUEST-----
    // 	MIIC6jCCAdICAQAwgaQxITAfBgNVBAMMGG15c3ViZG9tYWluLm15ZG9tYWluLmNv
    // 	bTELMAkGA1UEBhMCR0IxDjAMBgNVBAgMBVlvcmtzMQ0wCwYDVQQHDARZb3JrMSEw
    // 	HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxCzAJBgNVBAsMAklUMSMw
    // 	IQYJKoZIhvcNAQkBFhRzdXBwb3J0QG15ZG9tYWluLmNvbTCCASIwDQYJKoZIhvcN
    // 	AQEBBQADggEPADCCAQoCggEBALnQ0un/wF8whk+gPuiAlf3qvx14jgAOV6Erm6EB
    // 	H7WACPCpnKcm/8KP+7uoPiwRQaENhMeCgf45vcivl2p6aAn/spLXyEkXyw2d8wFb
    // 	YYAGRkiz4Xf7ASJiKuwcOtORz+sSDzgtdfokHfXU1cYeFE2yQhSdLUY5fMn425+g
    // 	KoEEsRSjSDe6AKru4+4iGNrLKd8pB9IA5/jOE139IkWlB9r5fEPD5bUTsgqXk9eb
    // 	68O0gc712V2eZK07N24lDmFC4bIMTD4csDWocR5hFHXj7NX7c8sOBDcpEb9mPIk4
    // 	elxubnhkfnjhOi4J3lDHcT/0ALnbLhf9LnaiKqs+5VcVZvECAwEAAaAAMA0GCSqG
    // 	SIb3DQEBBQUAA4IBAQC0AETLIcP3foh5nbu2hVFS8uCUNZ5hEIR1eXmYZmZoBQq2
    // 	26ZAoT4CZwixlggC+n7WvAXJ5Pzxpl4wLV4loTiQzaKPX1w0ERo5ZRwLy0n56oG2
    // 	6QG+WTViT1C8rlgtVwkCFNOXr0kSSRs8FdaPllqKxK1hxYSL7zwNpumsk39F2cDt
    // 	vhcekvH0V3BuGrQFm3dKN/0azW6GOod9+Vq4VzSyOe3kp15oxLBsZOFOu/REujcw
    // 	Tzu2jt1asQKUm60CZ9wNHpYepR0Ww40uP1slbehEaFDa6V8b60/tlHHmBbJ4/fy5
    // 	hJnYCvjzFz4O9VtT+JtP9ldRHWV3KpZ8ne3AjD+F
    // 	-----END CERTIFICATE REQUEST-----

}

chilkatExample();