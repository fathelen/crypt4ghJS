# Crypt4GH-JS 

Crypt4GH-JS is a JavaScript implementation of the standard file container format crypt4GH from the Global Alliance for Genomics and Health (GA4GH).
Crypt4GH was developed to ensure secured storing and sharing of sensitive data. 

Crypt4GH-JS has been implemented in JavaScript and is therefore applicable to all contemporary browser systems and offers all the prescribed parameters developed for Crypt4GH by the GA4GH.

## Installation 
crypt4GH-JS can be installated via the crypt4gh_js npm package and the crypt4ghJS GitHub repository. 
### Installation with npm: 
The npm package can be found here: [crypt4GH-JS](https://www.npmjs.com/package/crypt4gh_js) <br>
To install crypt4GH_JS via npm use:
```sh

npm i crypt4gh_js

```

 
 ### Installation from git: 
 To use the latest GitHub source install the package via: 
 ```sh

git clone https:https://github.com/fathelen/crypt4ghJS
npm i ./crypt4ghJS

```
 


## Usage 
The usage of the diffrent task, that can be handled via crypt4GH_JS, are shown in  the [example node file](https://github.com/fathelen/crypt4ghJS/blob/master/test/bench.js) <br>
and in the [example web file](https://github.com/fathelen/crypt4ghJS/blob/master/src/index.js) <br>
The single tasks will be explained in the following: <br>

### Generate keys 
The [crypt4GH specification](http://samtools.github.io/hts-specs/crypt4gh.pdf) prescribes the format of the keypair, that can be used for crypt4GH files. <br>
The format has to be like: <br>
 ```text

-----BEGIN CRYPT4GH PUBLIC KEY-----
Sw8o+Bpejno2FkDq23D2Q6GAOzq7Zy5a+brAqEgavEE=
-----END CRYPT4GH PUBLIC KEY-----

-----BEGIN CRYPT4GH PRIVATE KEY-----
YzRnaC12MQAGc2NyeXB0ABQAAAAAxr0v09Ec5NDcYKA7Ez4R5AARY2hhY2hhMjBfcG9seTEzMDUAPEfrI78aV6HMW78I51HwqMcPXyoqUACg0PQ4pijMGmlHMwjLdj5s8c3mjSR4MKjMQ6tkP5wT3KiOdKgxsQ==
-----END CRYPT4GH PRIVATE KEY-----
```


For node:
 ```javascript

async function generateKeys (secFile, pubFile, password) {
   const keys = await crypt4GHJS.keygen.keygen(password)
   fs.writeFile(secFile, keys[0], (err) => {
    if (err) {
      console.log(err)
    }
  })
  fs.writeFile(pubFile, keys[1], (err) => {
    if (err) {
      console.log(err)
    }
  })
}

generateKeys('secret_key_file', 'public_key_file', 'passwort')

```
For web use: 
 ```javascript

async function keyfile () {
  const password = await document.getElementById('psw').value
  const result = await crypt4GHJS.keygen.keygen(password)
  return result
}

```

### Encrypt data 

### Decrypt data

### Reencrypt data

### Rearrange data 

### Check keyfiles 

### Check fileformat

## Examples

## Crypt4GH Specification 

referring to: [crypt4GH specification](http://samtools.github.io/hts-specs/crypt4gh.pdf)

