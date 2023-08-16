import * as Kilt from '@kiltprotocol/sdk-js'
import { DidResourceUri, EncryptCallback } from '@kiltprotocol/types'
import {
  blake2AsU8a,
  keyExtractPath,
  keyFromPath,
  mnemonicToMiniSecret,
  sr25519PairFromSeed,
} from '@polkadot/util-crypto'

export function calculateKeyAgreementKeyFromMnemonic(mnemonic: string): Kilt.KiltEncryptionKeypair {
  const secretKeyPair = sr25519PairFromSeed(mnemonicToMiniSecret(mnemonic))
  const { path } = keyExtractPath('//did//keyAgreement//0')
  const { secretKey } = keyFromPath(secretKeyPair, path, 'sr25519')
  return Kilt.Utils.Crypto.makeEncryptionKeypairFromSeed(blake2AsU8a(secretKey))
}

export function getDefaultEncryptCallback(keyAgreement: Kilt.DidEncryptionKey, did: Kilt.DidUri): EncryptCallback {
  const keyUri: DidResourceUri = `${did}${keyAgreement.id}`

  async function encrypt({ data, peerPublicKey }: Parameters<EncryptCallback>[0]) {
    const { box, nonce } = Kilt.Utils.Crypto.encryptAsymmetric(data, peerPublicKey, keyAgreement.secretKey)
    return {
      data: box,
      nonce,
      keyUri,
    }
  }

  return encrypt
}
