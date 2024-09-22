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

## Libraries Used

- xml-crypto: ^6.0.0
- xmldom: ^0.6.0
- xpath: ^0.0.32
