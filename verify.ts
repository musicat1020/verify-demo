

import { randomBytes } from 'crypto'
import secp256k1 from 'secp256k1'
import sha256 from 'sha256'
import vc from './vc.json'
import vp from './vp.json'
import issuerDidDocument from './issuerDidDocument.json'
import holderDidDocument from './holderDidDocument.json'
import dotenv from 'dotenv';
dotenv.config();

const issPubKey = process.env.ISSUER_PUBLIC_KEY
const issPriKey = process.env.ISSUER_PRIVATE_KEY

const holderPubKey = process.env.HOLDER_PUBLIC_KEY
const holderPriKey = process.env.HOLDER_PRIVATE_KEY

const generateSeed = () => {
  let privKey
  // generate privKey
  do {
    privKey = randomBytes(32)
  } while (!secp256k1.privateKeyVerify(privKey))

  // get the public key in a compressed format
  const pubKey = secp256k1.publicKeyCreate(privKey)

  console.log("private key", Buffer.from(privKey).toString('hex'))
  console.log("public key", Buffer.from(pubKey).toString('hex'))

}

const verify = (inputJson: any, type: any, pubKey: any) => {
  //get signature
  const signMessage = inputJson.proof.signatureValue
  const signatureValue = Buffer.from(signMessage, 'hex')
  let result = false

  //convert json to unit8array
  delete inputJson.proof
  const jsonString = JSON.stringify(inputJson);
  const hash = sha256(jsonString)
  const msg = Buffer.from(hash, 'hex')

  switch (type) {
    case 'secp256k1':
      result = secp256k1.ecdsaVerify(signatureValue, msg, Buffer.from(pubKey, 'hex'))
      break

    default:
      console.log("does not support this type:", type)

  }
  return result
}

const signMessage = (jsonMsg: any, hexPrivKey: any) => {
  // convert hex to unit8array
  const privKey = Buffer.from(hexPrivKey, 'hex')

  //convert json to unit8array
  delete jsonMsg.proof
  const jsonString = JSON.stringify(jsonMsg);
  const hash = sha256(jsonString)
  const msg = Buffer.from(hash, 'hex')
  console.log("json>>", jsonString)

  // sign the message
  const sigObj = secp256k1.ecdsaSign(msg, privKey)
  console.log("sigObj>>", Buffer.from(sigObj.signature).toString('hex'))

}

const verifyDid = (didDoc: any) => {
  let pubKey: string = ''
  let type: string = ''
  let result = false
  const creator = didDoc.proof.creator
  const auth = didDoc.authentication[0]
  const vmId = didDoc.verificationMethod[0].id

  //這部分還不太確定，要再了解 get pubKey form id 的流程 
  if (creator == auth && auth == vmId) {
    type = didDoc.verificationMethod[0].type
    pubKey = didDoc.verificationMethod[0].publicKeyMultubase
  }

  result = verify(didDoc, type, pubKey)
  return result
}


const verifyVc = (vc: any, didDocument: any) => {
  let type = ''
  let pubKey = ''
  let result = false
  //
  const assert = didDocument.assertionMethod[0]

  //verify vc & verify issuer did
  didDocument.verificationMethod.forEach((vm: { id: any; type: string; publicKeyMultubase: string }) => {
    if (vm.id == assert) {
      type = vm.type
      pubKey = vm.publicKeyMultubase
      result = (verify(vc, type, pubKey) && verifyDid(didDocument))
    }

  });

  return result
}

//verify holder did -> vp ->(vc 包含issuer did) 
export const verifyVp = (vp: any, holderDidDocument: any, issuerDidDocument: any) => {
  // TODO:find did doc via query blockchain ?

  const vpCreator = vp.proof.creator

  let result = false
  let type = ''
  let pubKey = ''

  const holderDidVerification = verifyDid(holderDidDocument)
  if (holderDidVerification) {

    holderDidDocument.verificationMethod.forEach((vm: { controller: any; type: string; publicKeyMultubase: string }) => {
     
      //這部分邏輯不確定
      if (vm.controller == vpCreator) {
        type = vm.type
        pubKey = vm.publicKeyMultubase
      }
    });

    const vpVerification = verify(vp, type, pubKey)
    if (vpVerification) {
      const vc = vp.verifiableCredential[0]
      const vcVerification = verifyVc(vc, issuerDidDocument)
      result = vcVerification
    }
  }
  return result
}

// generateSeed()
// signMessage(holderDidDocument, holderPriKey)
// verifyDid(holderDidDocument)
// verifyVc(vc, issuerDidDocument)
// verifyVp(vp, holderDidDocument, issuerDidDocument)
