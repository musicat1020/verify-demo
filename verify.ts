import { randomBytes } from 'crypto'
import secp256k1 from 'secp256k1'
import sha256 from 'sha256'
import dotenv from 'dotenv'
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
  const hasAuth = didDoc.authentication.find((id: string) => id == creator)
  const hasVmId = didDoc.verificationMethod.find((vm: any) => vm.id == creator)

  //if creator == authentication == verificationMethod
  if (hasAuth && hasVmId) {
    type = hasVmId.type
    pubKey = hasVmId.publicKeyMultubase
  }

  result = verify(didDoc, type, pubKey)
  return result
}


const verifyVc = (vc: any, didDoc: any) => {
  let type = ''
  let pubKey = ''
  let result = false
  const creator = vc.proof.creator
  const hasAssert = didDoc.assertionMethod.find((id: string) => id.includes(creator))
  const hasVmId = didDoc.verificationMethod.find((vm: any) => vm.id.includes(creator))

  //verify vc & verify issuer did
  if (hasAssert && hasVmId) {
    type = hasVmId.type
    pubKey = hasVmId.publicKeyMultubase
    result = (verify(vc, type, pubKey) && verifyDid(didDoc))
  }

  return result
}

//verify holder did -> vp ->(vc 包含issuer did) 
export const verifyVp = (vp: any, holderDidDocument: any, issuerDidDocument: any) => {
  const vpCreator = vp.proof.creator

  let result = false
  let type = ''
  let pubKey = ''

  const holderDidVerification = verifyDid(holderDidDocument)
  if (holderDidVerification) {

    const hasVmId = holderDidDocument.verificationMethod.find((vm: any) => vm.id.includes(vpCreator))

    if (hasVmId) {
      type = hasVmId.type
      pubKey = hasVmId.publicKeyMultubase
      const vpVerification = verify(vp, type, pubKey)

      if (vpVerification) {
        for (let v = 0; v < vp.verifiableCredential.length; v++) {
          const vc = vp.verifiableCredential[v]
          const vcVerification = verifyVc(vc, issuerDidDocument)
          result = vcVerification
          if (result == false) {
            break
          }

        }
      }

    }

  }
  return result
}

