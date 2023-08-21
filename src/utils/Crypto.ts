import {
  DidResourceUri,
  EncryptCallback,
  KiltEncryptionKeypair,
  DecryptCallback,
  DidUri,
  KiltKeyringPair,
  SignCallback,
  DidDocument,
  SignRequestData,
  VerificationKeyRelationship,
  UriFragment,
  DidVerificationKey,
} from '@kiltprotocol/types'
import { Utils, Did } from '@kiltprotocol/sdk-js'
import {
  blake2AsU8a,
  keyExtractPath,
  keyFromPath,
  mnemonicToMiniSecret,
  sr25519PairFromSeed,
} from '@polkadot/util-crypto'
import { KeypairType } from '@polkadot/util-crypto/types'

function calculateKeyAgreementKeyFromMnemonic(mnemonic: string): KiltEncryptionKeypair {
  const secretKeyPair = sr25519PairFromSeed(mnemonicToMiniSecret(mnemonic))
  const { path } = keyExtractPath('//did//keyAgreement//0')
  const { secretKey } = keyFromPath(secretKeyPair, path, 'sr25519')
  return Utils.Crypto.makeEncryptionKeypairFromSeed(blake2AsU8a(secretKey))
}

export function getDefaultEncryptCallback(keyUri: DidResourceUri, mnemonic: string): EncryptCallback {
  const keyAgreement = calculateKeyAgreementKeyFromMnemonic(mnemonic)

  async function encrypt({ data, peerPublicKey }: Parameters<EncryptCallback>[0]) {
    const { box, nonce } = Utils.Crypto.encryptAsymmetric(data, peerPublicKey, keyAgreement.secretKey)
    return {
      data: box,
      nonce,
      keyUri,
    }
  }

  return encrypt
}

export function getDefaultDecryptCallback(mnemonic: string): DecryptCallback {
  const keyAgreement = calculateKeyAgreementKeyFromMnemonic(mnemonic)

  async function decrypt({ data, peerPublicKey, nonce }: Parameters<DecryptCallback>[0]) {
    const decryptedBytes = Utils.Crypto.decryptAsymmetric({ box: data, nonce }, peerPublicKey, keyAgreement.secretKey)

    if (!decryptedBytes) {
      throw new Error('Decrypt fail.')
    }

    return { data: decryptedBytes }
  }

  return decrypt
}

export function getDidUriFromDidResourceUri(didResourceUri: DidResourceUri): DidUri {
  return didResourceUri.substring(didResourceUri.indexOf('#')) as DidUri
}

export function getDefaultSignCallback(
  mnemonic: string,
  keyRelationship: VerificationKeyRelationship = 'assertionMethod',
  type?: KeypairType,
  ss58Format?: number
): SignCallback {
  const keyring = new Utils.Keyring({ type, ss58Format })
  const keypair = keyring.addFromMnemonic(mnemonic) as KiltKeyringPair

  const authentication = {
    ...keypair.derive('//did//0'),
    type,
  } as KiltKeyringPair

  const uri = Did.getFullDidUriFromKey(authentication)
  let didDocument: DidDocument | undefined
  let keyId: UriFragment | undefined
  let keyType: DidVerificationKey['type'] | undefined

  Did.resolve(uri).then((response) => {
    if (!response?.document) {
      throw new Error('Could not fetch DID document. Is DID on chain?')
    }
    const { document } = response
    keyId = document[keyRelationship]?.[0].id
    keyType = document[keyRelationship]?.[0].type
  })

  async function sign({ data }: SignRequestData) {
    if (!didDocument) {
      throw new Error('didDocument not fetched yet')
    }
    if (keyId === undefined || keyType === undefined) {
      throw new Error(`Key for purpose "${keyRelationship}" not found in did "${didDocument.uri}"`)
    }
    const signature = keypair.sign(data, { withType: false })
    return {
      signature,
      keyUri: `${didDocument.uri}#${keyId}` as DidResourceUri,
      keyType,
    }
  }
  return sign
}
