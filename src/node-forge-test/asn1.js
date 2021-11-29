var forge = require('../../vendor/node-forge');

var asn1 = forge.asn1;
var pki = forge.pki;

console.log(asn1)

const asn1String = 
	asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
		// AlgorithmIdentifier
		asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [
			// algorithm
			asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false, asn1.oidToDer(pki.oids.EdDSA25519).getBytes()),
			// parameters (null)
			asn1.create(asn1.Class.UNIVERSAL, asn1.Type.NULL, false, '')
		]),
		// subjectPublicKey
		asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,	String.fromCharCode(0x00) + ''),
		
		// subjectPublicKey
		asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, false,[1,6,5]),
		
		asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, 8),
		
		// subjectPublicKey
		asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BOOLEAN, false,	true),

	]);

	console.log("asn1: ", asn1String)
	const csi = pki.getCertificationRequestInfo(asn1String);
	console.log("csi", csi)
	// var bytes = asn1.toDer(csr);
	// digest and sign
	// let bt = bytes.getBytes();

	// console.log('asn1.bytes: ', bytes)
	/*
asn1.Type = {
  NONE:             0,
  BOOLEAN:          1,
  INTEGER:          2,
  BITSTRING:        3,
  OCTETSTRING:      4,
  NULL:             5,
  OID:              6,
  ODESC:            7,
  EXTERNAL:         8,
  REAL:             9,
  ENUMERATED:      10,
  EMBEDDED:        11,
  UTF8:            12,
  ROID:            13,
  SEQUENCE:        16,
  SET:             17,
  PRINTABLESTRING: 19,
  IA5STRING:       22,
  UTCTIME:         23,
  GENERALIZEDTIME: 24,
  BMPSTRING:       30
};

	*/
