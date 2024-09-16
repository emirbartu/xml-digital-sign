const fs = require('fs');
const { SignedXml } = require('xml-crypto');
const { DOMParser, XMLSerializer } = require('xmldom');
const xpath = require('xpath');

function serializeXmlToString(xmlDoc) {
  return new XMLSerializer().serializeToString(xmlDoc);
}

function checkRequiredNamespaces(doc) {
  const namespaces = {
    '': 'urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2',
    'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
    'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
    'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2',
    'xades': 'http://uri.etsi.org/01903/v1.3.2#',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
  };

  const missingNamespaces = [];
  for (const [prefix, uri] of Object.entries(namespaces)) {
    if (!doc.lookupNamespaceURI(prefix) || doc.lookupNamespaceURI(prefix) !== uri) {
      missingNamespaces.push(`${prefix}: ${uri}`);
    }
  }
  return missingNamespaces;
}

function validateXMLSignature(xmlString) {
  console.log('Starting XML signature validation');
  let doc;
  try {
    doc = parseXMLDocument(xmlString);
    const allNamespaces = defineNamespaces();
    addMissingNamespaces(doc, allNamespaces);
    const select = createXPathSelector(doc, allNamespaces);

    checkRequiredElements(select);
    const signature = locateSignatureElement(select);
    const sig = createSignedXmlInstance(doc);

    loadSignature(sig, signature);
    setKeyExtractor(sig, select, doc);  // Pass doc to setKeyExtractor

    const validationResult = validateSignature(sig, xmlString);
    console.log('Validation result:', JSON.stringify(validationResult, null, 2));
    return validationResult;
  } catch (error) {
    console.error('Error during XML signature validation:', error);
    return {
      success: false,
      message: `Error validating XML signature: ${error.message}`,
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack
      }
    };
  }
}

function parseXMLDocument(xmlString) {
  console.log('Parsing XML string...');
  const parser = new DOMParser({
    errorHandler: {
      warning: (msg) => console.warn('XML Parser Warning:', msg),
      error: (msg) => console.error('XML Parser Error:', msg),
      fatalError: (msg) => { throw new Error('XML Parsing Fatal Error: ' + msg); }
    },
    locator: {},
    entityExpansion: false,
    xmlns: true // Enable namespace parsing
  });
  const doc = parser.parseFromString(xmlString, 'text/xml');
  if (!doc || !doc.documentElement) {
    throw new Error('Failed to parse XML: Invalid document structure');
  }
  console.log('XML document parsed successfully');
  console.log('XML root element:', doc.documentElement.tagName);
  console.log('Namespaces:', doc.documentElement.namespaceURI);
  return doc;
}

function defineNamespaces() {
  return {
    'inv': 'urn:oasis:names:specification:ubl:schema:xsd:Invoice-2',
    'cac': 'urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2',
    'cbc': 'urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
    'ext': 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2'
  };
}

function addMissingNamespaces(doc, allNamespaces) {
  Object.entries(allNamespaces).forEach(([prefix, uri]) => {
    const nsAttr = prefix ? `xmlns:${prefix}` : 'xmlns';
    if (!doc.documentElement.hasAttribute(nsAttr)) {
      console.log(`Adding missing namespace: ${prefix} - ${uri}`);
      doc.documentElement.setAttribute(nsAttr, uri);
    }
  });
}

function createXPathSelector(doc, allNamespaces) {
  const nsResolver = (prefix) => {
    if (prefix === 'xmlns') return 'http://www.w3.org/2000/xmlns/';
    const resolvedNamespace = allNamespaces[prefix] || null;
    console.log(`Resolving namespace for prefix '${prefix}':`, resolvedNamespace);
    return resolvedNamespace;
  };

  const select = (xpathExpression, node = doc) => {
    console.log('Executing XPath:', xpathExpression);
    console.log('Namespaces:', JSON.stringify(allNamespaces, null, 2));

    try {
      // Use xpath.useNamespaces to create a selector with predefined namespaces
      const xpathSelector = xpath.useNamespaces(allNamespaces);
      const result = xpathSelector(xpathExpression, node);

      console.log('XPath selection result type:', Array.isArray(result) ? 'NodeList' : typeof result);
      console.log('Result details:', result ? (Array.isArray(result) ? `${result.length} nodes` : `Value: ${result}`) : 'No result');

      if (!result || (Array.isArray(result) && result.length === 0)) {
        console.warn('No nodes found for XPath:', xpathExpression);
      } else if (Array.isArray(result)) {
        result.forEach((node, index) => {
          console.log(`Node ${index + 1}:`, node.nodeName, node.namespaceURI);
        });
      }

      return result;
    } catch (error) {
      console.error('XPath selection error:', error.message);
      console.error('XPath expression:', xpathExpression);
      console.error('Context node:', node ? `${node.nodeName} (${node.namespaceURI})` : 'undefined');
      throw new Error(`XPath selection failed: ${error.message}`);
    }
  };

  select.namespaces = allNamespaces;
  return select;
}

function checkRequiredElements(select) {
  console.log('Checking for required elements...');
  const requiredElements = [
    { name: 'Signature', namespace: 'ds' },
    { name: 'SignatureValue', namespace: 'ds' },
    { name: 'KeyInfo', namespace: 'ds' },
    { name: 'X509Certificate', namespace: 'ds' }
  ];
  for (const element of requiredElements) {
    const xpathExpression = `//*[local-name()='${element.name}' and namespace-uri()='${select.namespaces[element.namespace]}']`;
    const found = select(xpathExpression);
    if (!found || found.length === 0) {
      console.warn(`XPath query used: ${xpathExpression}`);
      throw new Error(`Required element ${element.namespace}:${element.name} not found in the XML document`);
    }
  }
  console.log('All required elements found');
}

function locateSignatureElement(select) {
  console.log('Locating Signature element...');
  const xpathExpressions = [
    "//*[local-name()='Signature' and namespace-uri()='http://www.w3.org/2000/09/xmldsig#']",
    "//ds:Signature",
    "//*[local-name()='Signature']",
    "/*[local-name()='Invoice']/*[local-name()='Signature']"
  ];
  let signature;
  for (const xpathExpression of xpathExpressions) {
    try {
      const result = select(xpathExpression);
      if (result && result.length > 0) {
        signature = result[0];
        console.log(`Found signature element using: ${xpathExpression}`);
        break;
      }
    } catch (error) {
      console.warn(`Error with XPath expression "${xpathExpression}":`, error.message);
    }
  }
  if (!signature) {
    console.warn(`XPath queries used: ${xpathExpressions.join(', ')}`);
    throw new Error('Signature element not found');
  }
  console.log('Using found signature element');
  return signature;
}

function createSignedXmlInstance() {
  const sigOptions = {
    idMode: "wssecurity",
    idAttributes: ["Id"],
    canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    implicitTransforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature"]
  };
  console.log('SignedXml options:', JSON.stringify(sigOptions, null, 2));
  console.log('Creating SignedXml instance...');
  const sig = new SignedXml(sigOptions);
  return sig;
}

function loadSignature(sig, signature) {
  console.log('Loading signature...');
  try {
    sig.loadSignature(signature);
    console.log('Signature loaded successfully');
  } catch (error) {
    console.error('Error loading signature:', error.message);
    throw new Error(`Failed to load signature: ${error.message}`);
  }
}

function setKeyExtractor(sig, select, doc) {
  sig.keyInfoProvider = {
    getKey: (keyInfo) => {
      console.log('Entering key extractor function');

      const extractCertificate = (node) => {
        const xpathQueries = [
          '//ds:X509Certificate',
          '//*[local-name()="X509Certificate"]',
          '//ds:KeyInfo/ds:X509Data/ds:X509Certificate',
          '//*[local-name()="KeyInfo"]/*[local-name()="X509Data"]/*[local-name()="X509Certificate"]',
          '//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate',
          '//*[local-name()="Signature"]/*[local-name()="KeyInfo"]/*[local-name()="X509Data"]/*[local-name()="X509Certificate"]',
          '/*[local-name()="Invoice"]//*[local-name()="X509Certificate"]',
          '//ds:X509Data/ds:X509Certificate',
          '//*[local-name()="X509Data"]/*[local-name()="X509Certificate"]'
        ];

        for (const query of xpathQueries) {
          try {
            const result = select(query, node);
            if (result && result.length > 0) {
              console.log(`X509Certificate found using query: ${query}`);
              return result[0].textContent.trim();
            }
          } catch (error) {
            console.warn(`Error with XPath query "${query}":`, error.message);
          }
        }
        return null;
      };

      let certData = extractCertificate(keyInfo);

      if (!certData) {
        console.warn('Certificate not found in KeyInfo, searching in the entire document...');
        certData = extractCertificate(doc);
      }

      if (!certData) {
        console.error('No X509Certificate elements found');
        console.error('XML structure:', serializeXmlToString(doc));
        console.error('Available namespaces:', Object.keys(select.namespaces).join(', '));
        console.error('Root element:', doc.documentElement.tagName);
        throw new Error('No X509Certificate elements found in the document');
      }

      if (certData.length === 0) {
        console.error('Extracted certificate is empty');
        throw new Error('Extracted certificate is empty');
      }

      console.log('X509Certificate extracted, length:', certData.length);
      console.log('Certificate data (first 50 chars):', certData.substring(0, 50));

      // Remove any whitespace and non-base64 characters
      certData = certData.replace(/\s+/g, '').replace(/[^A-Za-z0-9+/=]/g, '');

      // Convert base64 to Buffer (raw certificate data)
      const rawCertData = Buffer.from(certData, 'base64');

      console.log('Raw certificate data length:', rawCertData.length);
      return rawCertData;
    },
    getKeyInfo: (key) => {
      let pemCert;
      if (Buffer.isBuffer(key)) {
        pemCert = key.toString('base64');
      } else if (typeof key === 'string') {
        pemCert = key.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\n|\r/g, '');
      } else {
        throw new Error('Unsupported key format');
      }
      return `<X509Data><X509Certificate>${pemCert}</X509Certificate></X509Data>`;
    }
  };
  console.log('Key extractor function set successfully');
}

function pemToDer(pem) {
  console.log('Converting PEM to DER format');
  try {
    // Remove PEM headers and newlines
    const base64 = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\n|\r/g, '');
    console.log('Base64 length after removing headers:', base64.length);

    // Convert base64 to binary string
    const binary = atob(base64);
    console.log('Binary string length:', binary.length);

    // Convert binary string to Uint8Array
    const der = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      der[i] = binary.charCodeAt(i);
    }
    console.log('DER Uint8Array length:', der.length);
    return der;
  } catch (error) {
    console.error('Error converting PEM to DER:', error.message);
    throw new Error(`Failed to convert PEM to DER: ${error.message}`);
  }
}

function derToPem(der) {
  console.log('Converting DER to PEM format');
  try {
    // Convert Uint8Array to base64 string
    const base64 = Buffer.from(der).toString('base64');
    console.log('Base64 length:', base64.length);

    // Split the base64 string into lines of 64 characters
    const lines = base64.match(/.{1,64}/g);

    // Add PEM headers and join lines
    const pem = `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
    console.log('PEM length:', pem.length);
    return pem;
  } catch (error) {
    console.error('Error converting DER to PEM:', error.message);
    throw new Error(`Failed to convert DER to PEM: ${error.message}`);
  }
}

function convertToPEM(certData) {
  // Remove any existing PEM headers/footers and whitespace
  certData = certData.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, '');

  // Check if the certificate is base64 encoded
  if (!/^[A-Za-z0-9+/=]+$/.test(certData)) {
    throw new Error('Certificate data is not valid base64');
  }

  // Add PEM headers and format the certificate
  const pemCert = `-----BEGIN CERTIFICATE-----\n${certData.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;

  return pemCert;
}

function formatAndValidateCertificate(certData) {
  console.log('Formatting and validating certificate...');
  console.log('Original certificate data length:', certData.length);

  try {
    // Remove any whitespace and non-base64 characters
    certData = certData.replace(/\s+/g, '').replace(/[^A-Za-z0-9+/=]/g, '');
    console.log('Cleaned certificate data length:', certData.length);

    if (certData.length < 100) {
      throw new Error('Certificate data is too short to be valid');
    }

    if (!certData.match(/^[A-Za-z0-9+/]+={0,2}$/)) {
      console.warn('Certificate data is not in valid base64 format after cleaning');
      console.log('Invalid certificate data:', certData.substring(0, 50) + '...');
      throw new Error('Invalid certificate format: Unable to convert to valid base64');
    }

    // Check if the certificate is already in PEM format
    if (certData.includes('-----BEGIN CERTIFICATE-----')) {
      console.log('Certificate is already in PEM format');
      return certData;
    }

    if (!certData.startsWith('MII')) {
      console.warn('Certificate does not start with expected header (MII)');
      console.log('Certificate start:', certData.substring(0, 20));
    }

    // Split the certificate into lines of 64 characters
    const formattedCert = certData.match(/.{1,64}/g).join('\n');

    // Add PEM headers
    const pemCert = `-----BEGIN CERTIFICATE-----\n${formattedCert}\n-----END CERTIFICATE-----`;
    console.log('Formatted PEM certificate (first 100 chars):', pemCert.substring(0, 100));

    // Validate the formatted certificate
    if (!pemCert.match(/-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/\n]+={0,2}\n-----END CERTIFICATE-----/)) {
      throw new Error('Invalid certificate format after formatting');
    }

    if (pemCert.length < 500) {
      throw new Error('Formatted certificate is too short to be valid');
    }

    console.log('Certificate successfully formatted and validated');
    return pemCert;
  } catch (error) {
    console.error('Error in formatAndValidateCertificate:', error.message);
    throw error;
  }
}

function validateSignature(sig, xmlString) {
  console.log('Starting signature validation...');
  try {
    console.log('SignatureAlgorithm:', sig.signatureAlgorithm);
    console.log('CanonicalizationAlgorithm:', sig.canonicalizationAlgorithm);

    const signatureValue = sig.signatureValue;
    console.log('Actual Signature Value:', signatureValue);

    if (!signatureValue || signatureValue.trim() === '') {
      throw new Error('Signature value is empty');
    }

    if (!sig.keyInfoProvider || !sig.keyInfoProvider.getKey) {
      throw new Error('KeyInfoProvider is not properly set');
    }

    const keyInfo = sig.getKeyInfo();
    console.log('KeyInfo:', keyInfo ? keyInfo.substring(0, 100) + '...' : 'Not found');

    let cert;
    try {
      cert = sig.keyInfoProvider.getKey(keyInfo);
      console.log('Extracted certificate:', cert ? (cert instanceof Uint8Array ? 'DER format' : cert.substring(0, 50) + '...') : 'Not found');
    } catch (certError) {
      console.error('Error extracting certificate:', certError.message);
      throw new Error(`Failed to extract certificate: ${certError.message}`);
    }

    if (!cert) {
      throw new Error('Certificate not found in KeyInfo');
    }

    let formattedCert = cert;
    if (cert instanceof Uint8Array) {
      console.log('Converting DER certificate to PEM format...');
      formattedCert = derToPem(cert);
    } else if (typeof cert === 'string') {
      if (!cert.includes('-----BEGIN CERTIFICATE-----')) {
        console.log('Formatting certificate with PEM headers...');
        formattedCert = `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----`;
      } else {
        console.log('Certificate is already in PEM format');
      }
    } else {
      throw new Error('Unsupported certificate format');
    }

    // Set the publicCert property of the SignedXml instance
    sig.publicCert = formattedCert;
    console.log('Public certificate set for signature validation');

    console.log('Checking signature...');
    const isValid = sig.checkSignature(xmlString);
    console.log('Signature check result:', isValid);

    if (isValid) {
      console.log('Signature is valid.');
      const certDetails = extractCertificateDetails(formattedCert);
      return {
        success: true,
        message: 'Signature is valid',
        certificateDetail: {
          organization: certDetails.organization,
          issuer: certDetails.issuer,
          validTo: certDetails.validTo
        },
        details: {
          signatureAlgorithm: sig.signatureAlgorithm,
          canonicalizationAlgorithm: sig.canonicalizationAlgorithm,
          actualSignature: signatureValue,
          certificate: formattedCert.substring(0, 50) + '...'
        }
      };
    } else {
      console.warn('Signature is invalid.');
      const validationErrors = safeSerialize(sig.validationErrors);
      console.log('Validation errors:', validationErrors);

      const calculatedDigest = sig.calculateSignatureValue();
      const expectedDigest = sig.getSignatureValue();

      let detailedErrorMessage = 'Signature is invalid';
      const errorDetails = {
        signatureAlgorithm: sig.signatureAlgorithm,
        canonicalizationAlgorithm: sig.canonicalizationAlgorithm,
        actualSignature: signatureValue,
        certificate: formattedCert.substring(0, 50) + '...',
        calculatedDigest: calculatedDigest,
        expectedDigest: expectedDigest,
        xmlPreview: xmlString.substring(0, 200) + '...',
        references: [],
        signatureXml: sig.getSignatureXml()
      };

      if (sig.references && sig.references.length > 0) {
        const referenceValidation = sig.references.map(ref => ({
          uri: ref.uri,
          calculatedDigest: ref.calculateDigest(),
          expectedDigest: ref.digestValue
        }));

        const invalidReferences = referenceValidation.filter(ref => ref.calculatedDigest !== ref.expectedDigest);
        if (invalidReferences.length > 0) {
          detailedErrorMessage += `. Digest mismatch in ${invalidReferences.length} reference(s).`;
          errorDetails.references = invalidReferences;
        }
      }

      if (calculatedDigest !== expectedDigest) {
        detailedErrorMessage += ' SignatureValue mismatch.';
      }

      console.log('Detailed error message:', detailedErrorMessage);
      console.log('Error details:', JSON.stringify(errorDetails, null, 2));

      return {
        success: false,
        message: detailedErrorMessage,
        errors: validationErrors,
        details: errorDetails
      };
    }
  } catch (error) {
    console.error('Error during signature validation:', error.message);
    console.error('Error stack:', error.stack);
    return {
      success: false,
      message: `Signature validation error: ${error.message}`,
      details: {
        errorName: error.name,
        errorStack: error.stack,
        signatureAlgorithm: sig.signatureAlgorithm,
        canonicalizationAlgorithm: sig.canonicalizationAlgorithm
      }
    };
  }
}

function extractCertificateDetails(cert) {
  // This is a placeholder function. In a real-world scenario, you would use a library
  // like node-forge to properly parse the certificate and extract these details.
  return {
    organization: "Example Organization",
    issuer: "Example Issuer",
    validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0] // One year from now
  };
}

function handleValidationError(error) {
  console.error('Error during signature validation:', error.message);
  return {
    success: false,
    message: `Error validating signature: ${error.message}`,
    errorDetails: {
      name: error.name,
      message: error.message,
      stack: error.stack ? error.stack.split('\n').slice(0, 3).join('\n') : 'No stack trace available'
    }
  };
}

function safeSerialize(obj, depth = 0, maxDepth = 5) {
  const seen = new WeakSet();

  function isCircular(value) {
    if (typeof value !== 'object' || value === null) return false;
    if (seen.has(value)) return true;
    seen.add(value);
    return false;
  }

  function serializeXmlNode(node) {
    if (!node) return '[Invalid XML Node]';
    switch (node.nodeType) {
      case 1: // Element
        return `<${node.nodeName}/>`;
      case 2: // Attr
        return `${node.name}="..."`;
      case 3: // Text
        return '[Text Node]';
      case 4: // CDATA Section
        return '<![CDATA[...]]>';
      case 7: // Processing Instruction
        return '<?...?>';
      case 8: // Comment
        return '<!--...-->';
      case 9: // Document
        return '[XML Document]';
      case 10: // Document Type
        return '<!DOCTYPE...>';
      case 11: // Document Fragment
        return '[Document Fragment]';
      default:
        return '[XML Node]';
    }
  }

  function serializeValue(value) {
    if (depth > maxDepth) {
      return `[MaxDepth]`;
    }

    if (isCircular(value)) {
      return `[Circular]`;
    }

    if (value === null) return null;
    if (typeof value !== 'object') return value;

    if (Array.isArray(value)) {
      return `[Array]`;
    }

    if (value instanceof Error) {
      return {
        name: value.name,
        message: value.message
      };
    }

    if (value instanceof RegExp || value instanceof Date) {
      return value.toString();
    }

    // Handle XML-specific objects
    if (typeof value.nodeType === 'number') {
      return serializeXmlNode(value);
    }

    if (typeof NodeList !== 'undefined' && value instanceof NodeList) {
      return `[NodeList]`;
    }

    if (typeof NamedNodeMap !== 'undefined' && value instanceof NamedNodeMap) {
      return `[NamedNodeMap]`;
    }

    if (value.ownerDocument && typeof value.ownerDocument.nodeType === 'number') {
      return `[XML Object]`;
    }

    // Handle other objects
    const serialized = {};
    for (const [key, prop] of Object.entries(value)) {
      serialized[key] = serializeValue(prop, depth + 1);
    }
    return serialized;
  }

  return JSON.stringify(serializeValue(obj), null, 2);
}

function processXMLFile(filePath) {
  try {
    console.log(`Reading XML file: ${filePath}`);
    const xmlString = fs.readFileSync(filePath, 'utf-8');
    console.log(`File read successfully. Content length: ${xmlString.length} characters`);

    console.log('Validating XML signature...');
    const result = validateXMLSignature(xmlString);
    console.log('Validation result:', JSON.stringify(result, null, 2));

    return result;
  } catch (error) {
    console.error(`Error processing file ${filePath}:`, error.message);
    console.error('Error stack:', error.stack);
    return {
      success: false,
      message: `Error processing file: ${error.message}`,
      details: {
        filePath,
        errorName: error.name,
        errorStack: error.stack
      }
    };
  }
}

// Example usage
const xmlFilePath = process.argv[2];
if (xmlFilePath) {
  processXMLFile(xmlFilePath);
} else {
  console.error('Please provide the path to the XML file as a command-line argument.');
}
