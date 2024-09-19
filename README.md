# XML Signature Validation Application

This application validates digital signatures of XML documents according to XMLDSig standards, with a focus on invoice documents.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/emirbartu/xml-digital-sign.git
   cd xml-digital-sign
   ```

2. Install dependencies:
   ```
   npm install
   ```

## Usage

Run the application with an XML file as input:

```
node index.js path/to/your/xml/file.xml
```

## Example XML Document Structure

A valid XML document should include the following elements:

```xml
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
         xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <!-- Invoice content -->
    <ds:Signature>
        <ds:SignedInfo>
            <!-- SignedInfo content -->
        </ds:SignedInfo>
        <ds:SignatureValue><!-- Base64-encoded signature value --></ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate><!-- Base64-encoded X.509 certificate --></ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
</Invoice>
```

## Expected Output

### For a valid signature:

```json
{
  "success": true,
  "message": "Signature is valid",
  "certificateDetail": {
    "organization": "Example Organization",
    "issuer": "Example Issuer",
    "validTo": "YYYY-MM-DD"
  }
}
```

### For an invalid signature:

```json
{
  "success": false,
  "message": "Signature is invalid",
  "errors": [
    "Detailed error message"
  ]
}
```

## Libraries Used

- xml-crypto: ^6.0.0
- xmldom: ^0.6.0
- xpath: ^0.0.32

## Key Features

- Validates ds:SignatureValue
- Extracts and processes X509Certificate
- Handles various CanonicalizationMethod algorithms
- Supports different XML document structures

## Evaluation Criteria

- Efficiency in processing large XML files
- Generality in handling different invoice document formats
- Code quality and maintainability

For more detailed information about the implementation, please refer to the `index.js` file.
