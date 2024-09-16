const fs = require('fs');
const { SignedXml } = require('xml-crypto');
const { DOMParser } = require('xmldom');

function validateXMLSignature(xmlString) {
  console.log('Starting XML signature validation');
  let doc;
  try {
    doc = new DOMParser().parseFromString(xmlString, 'text/xml');
    if (!doc || !doc.documentElement) {
      throw new Error('Failed to parse XML: Invalid document structure');
    }
    console.log('XML document parsed successfully');
    console.log('XML root element:', doc.documentElement.tagName);

    const signature = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0];
    if (!signature) {
      console.error('Signature element not found in the XML document');
      return { success: false, message: "Signature element not found" };
    }
    console.log('Signature element found');
    console.log('Signature XML:', signature.toString());

    const sigOptions = {
      idMode: "wssecurity",
      idAttributes: ["Id"],
      canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
      namespaceResolver: {
        '': 'urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2',
        'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
        'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
        'ccts': 'urn:oasis:names:specification:ubl:schema:xsd:CoreComponentParameters-2',
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
        'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
        'qdt': 'urn:oasis:names:specification:ubl:schema:xsd:QualifiedDatatypes-2',
        'sac': 'urn:sunat:names:specification:ubl:peru:schema:xsd:SunatAggregateComponents-1',
        'stat': 'urn:oasis:names:specification:ubl:schema:xsd:DocumentStatusCode-1.0',
        'udt': 'urn:un:unece:uncefact:data:draft:UnqualifiedDataTypesSchemaModule:2'
      }
    };
    console.log('SignedXml options:', JSON.stringify(sigOptions, null, 2));

    const sig = new SignedXml(doc, sigOptions);
    console.log('SignedXml instance created with custom options and namespaces');

    // Key extractor function
    sig.keyInfoProvider = {
      getKey: (keyInfo) => {
        console.log('Entering key extractor function');
        if (keyInfo && keyInfo.getElementsByTagNameNS) {
          console.log('KeyInfo is valid and has getElementsByTagNameNS method');
          const x509Data = keyInfo.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'X509Certificate');
          console.log('X509Certificate elements found:', x509Data.length);
          if (x509Data.length > 0) {
            const certData = x509Data[0].textContent;
            console.log('X509Certificate found and extracted, length:', certData.length);
            console.log('First 50 characters of certificate:', certData.substring(0, 50));
            return certData;
          } else {
            console.error('No X509Certificate elements found in KeyInfo');
          }
        } else {
          console.error('KeyInfo is invalid or missing getElementsByTagNameNS method');
          console.log('KeyInfo content:', keyInfo ? keyInfo.toString() : 'undefined');
        }
        console.error('Could not find X509Certificate element');
        throw new Error('Could not find X509Certificate element');
      }
    };
    console.log('Key extractor function set');

    sig.loadSignature(signature);
    console.log('Signature loaded successfully');
    console.log('Signature details:', {
      signingAlgorithm: sig.signatureAlgorithm,
      canonicalizationAlgorithm: sig.canonicalizationAlgorithm,
      references: sig.references.map(ref => ({
        uri: ref.uri,
        transforms: ref.transforms,
        digestAlgorithm: ref.digestAlgorithm
      }))
    });

    console.log('Checking signature...');
    const isValid = sig.checkSignature(doc);
    console.log('Signature check result:', isValid);
    if (!isValid) {
      console.log('Signature validation errors:', JSON.stringify(sig.validationErrors, null, 2));
      console.log('Signature algorithm:', sig.signatureAlgorithm);
      console.log('Canonicalization algorithm:', sig.canonicalizationAlgorithm);
      console.log('References:', JSON.stringify(sig.references, null, 2));
      console.log('Calculated digest:', sig.calculateSignatureValue());
      console.log('Expected digest:', sig.signingKey);
    }

    if (isValid) {
      const x509Cert = signature.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'X509Certificate')[0];
      if (!x509Cert) {
        console.warn('X509Certificate element not found in the signature');
      } else {
        console.log('X509Certificate found in the signature');
        const certData = x509Cert.textContent;
        console.log('Certificate data length:', certData.length);
        console.log('Certificate data (first 100 chars):', certData.substring(0, 100));
      }

      // Note: Parsing certificate details requires additional libraries.
      // For this example, we'll return placeholder values.
      // In a production environment, you'd use a library like node-forge to parse the certificate.
      console.log('Returning success result with placeholder certificate details');
      return {
        success: true,
        certificateDetail: {
          organization: "Example Organization",
          issuer: "Example Issuer",
          validTo: "2025-12-31"
        }
      };
    } else {
      console.error('Signature validation failed');
      return {
        success: false,
        message: "Invalid signature"
      };
    }
  } catch (error) {
    console.error('Error during signature validation:', error);
    console.error('Error stack:', error.stack);
    return {
      success: false,
      message: `Error validating signature: ${error.message}`
    };
  }
}

function processXMLFile(filePath) {
  try {
    console.log(`Reading XML file: ${filePath}`);
    const xmlString = fs.readFileSync(filePath, 'utf-8');
    console.log(`File read successfully. Content length: ${xmlString.length} characters`);

    console.log('Validating XML signature...');
    const result = validateXMLSignature(xmlString);
    console.log('Validation result:');
    console.log(JSON.stringify(result, null, 2));

    return result;
  } catch (error) {
    console.error(`Error processing file ${filePath}:`);
    console.error(`- Message: ${error.message}`);
    console.error(`- Stack: ${error.stack}`);
    return { success: false, message: `Error processing file: ${error.message}` };
  }
}

// Example usage
const xmlFilePath = process.argv[2];
if (xmlFilePath) {
  processXMLFile(xmlFilePath);
} else {
  console.error('Please provide the path to the XML file as a command-line argument.');
}
