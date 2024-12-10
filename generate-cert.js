
// generate-cert.js
import forge from "node-forge";
import fs from "fs";


function generateCertificate() {
    // Generate a key pair
    console.log('Generating key pair...');
    const keys = forge.pki.rsa.generateKeyPair(2048);

    // Create a certificate
    console.log('Creating certificate...');
    const cert = forge.pki.createCertificate();

    // Set certificate fields
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    // Add certificate attributes
    const attrs = [{
        name: 'commonName',
        value: 'localhost'
    }, {
        name: 'countryName',
        value: 'US'
    }, {
        shortName: 'ST',
        value: 'Local State'
    }, {
        name: 'localityName',
        value: 'Local City'
    }, {
        name: 'organizationName',
        value: 'Local Dev'
    }, {
        shortName: 'OU',
        value: 'Development'
    }];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    // Set extensions
    cert.setExtensions([{
        name: 'basicConstraints',
        cA: true
    }, {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true
    }, {
        name: 'subjectAltName',
        altNames: [{
            type: 2, // DNS
            value: 'localhost'
        }, {
            type: 7, // IP
            ip: '127.0.0.1'
        }]
    }]);

    // Self-sign the certificate
    cert.sign(keys.privateKey, forge.md.sha256.create());

    // Convert to PEM format
    const privPem = forge.pki.privateKeyToPem(keys.privateKey);
    const certPem = forge.pki.certificateToPem(cert);

    // Save files
    fs.writeFileSync('cert.key', privPem);
    fs.writeFileSync('cert.crt', certPem);

    console.log('Certificate generated successfully!');
}

// Generate the certificate
generateCertificate();