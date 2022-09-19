import {
  Did,
  KeystoreSigner,
  KeyringPair,
  VerificationKeyType,
  KeyRelationship,
} from '@kiltprotocol/sdk-js'
import Keyring from '@polkadot/keyring'
import * as FULL_DID from './fullDid.json'

import {
  createWellKnownDidConfig,
  getDidConfiguration,
} from './createWellKnownDidConfig'

describe('Well Known Did configuration', () => {
  const mnemonic =
    'caution divert long junior have conduct save spend right sun snake member'
  const keypair = new Keyring().addFromMnemonic(mnemonic)
  let did = await createFullDidFromSeed(paymentAccount, keypair)
  let attesterSign: KeystoreSigner

  it('create well known did config', () => {
    const b = ''
    const c = ''

    expect(createWellKnownDidConfig(attesterSign,'http://localhost:3000', FULL_DID.)).toBeCalled()
  })
})
