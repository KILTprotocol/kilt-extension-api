import {
  Did,
  KeystoreSigner,
  KeyringPair,
  VerificationKeyType,
  KeyRelationship,
  DidUri,
} from '@kiltprotocol/sdk-js'
import Keyring from '@polkadot/keyring'
import { mnemonicGenerate } from '@polkadot/util-crypto'
import FULL_DID from './fullDid.json'

import {
  createCredential,
  getDomainLinkagePresentation,
} from './wellKnownDidConfiguration'

describe('Well Known Did Configuration end to end', () => {
  const mnemonic = mnemonicGenerate()

  const keypair = new Keyring().addFromMnemonic(mnemonic)
  const did = FULL_DID
  let attesterSign: KeystoreSigner

  it('generate a well known did configuration credential', () => {
    const b = ''
    const c = ''

    expect(
      createCredential(
        attesterSign,
        'http://localhost:3000',
        'did:kilt:0x1234556789'
      )
    ).toBeCalled()
  })
})
