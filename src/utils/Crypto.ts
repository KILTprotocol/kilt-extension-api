import {
  DidResourceUri,
  EncryptCallback,
  KiltEncryptionKeypair,
  DecryptCallback,
  DidUri,
  KiltKeyringPair,
} from '@kiltprotocol/types'
import { Utils } from '@kiltprotocol/sdk-js'
import {
  blake2AsU8a,
  keyExtractPath,
  keyFromPath,
  mnemonicToMiniSecret,
  sr25519PairFromSeed,
} from '@polkadot/util-crypto'

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

export function getDefaultSignCallback(keypair: KiltKeyringPair) {
  return (didDocument) =>
    async function sign({ data, keyRelationship }) {
      const keyId = didDocument[keyRelationship]?.[0].id
      const keyType = didDocument[keyRelationship]?.[0].type
      if (keyId === undefined || keyType === undefined) {
        throw new Error(`Key for purpose "${keyRelationship}" not found in did "${didDocument.uri}"`)
      }
      const signature = keypair.sign(data, { withType: false })

      return {
        signature,
        keyUri: `${didDocument.uri}${keyId}`,
        keyType,
      }
    }
}
